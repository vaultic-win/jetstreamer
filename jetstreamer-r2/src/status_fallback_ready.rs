//! Delete a completed epoch's mutable status when its latest publication used
//! the authenticated status-only fallback. The raw publication bytes remain
//! the binding; this never invents a native status-publication receipt.
use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const PLAN_SCHEMA: &str = "jetstreamer-r2-fallback-ready-status-plan-v1";
const ANZA_PLAN_SCHEMA: &str = "jetstreamer-r2-anza-cadence-ready-status-plan-v1";
const COMPLETION_SCHEMA: &str = "horizon-status-only-correction-completion-v1";
const INTENT_SCHEMA: &str = "jetstreamer-r2-fallback-ready-status-delete-intent-v1";
const DELETION_SCHEMA: &str = "jetstreamer-r2-fallback-ready-status-deletion-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    bucket: String,
    epoch: u64,
    status_delete_authorized: bool,
    archive_or_sidecar_mutations: bool,
    fallback_completion: Bound,
    raw_status: Bound,
    #[serde(default)]
    operator_intent: Option<Bound>,
    #[serde(default)]
    operator_before: Option<Bound>,
    archive_receipt: Bound,
    deletion_intent: PathBuf,
    deletion_receipt: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FallbackCompletion {
    schema: String,
    epoch: u64,
    key: String,
    before_etag: String,
    after_etag: String,
    before_sha256: String,
    after_sha256: String,
    sampled_at_utc: String,
    phase: String,
    authenticated_exact_byte_readback: bool,
    conditional_header: String,
    archive_or_sidecar_mutation: bool,
}

#[derive(Debug, Deserialize)]
struct AnzaCadenceCompletion {
    epoch: u64,
    key: String,
    before_etag: String,
    after_etag: String,
    after_sha256: String,
    after_status: EpochStatus,
    authenticated_readback: bool,
    conditional_header: String,
    archive_publication_authorized: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorCompletion {
    epoch: u64,
    key: String,
    before_etag: String,
    new_etag: String,
    new_sha256: String,
    sampled_at_utc: String,
    owner: String,
    authenticated_exact_byte_readback: bool,
    archive_or_sidecar_mutation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorIntent {
    epoch: u64,
    key: String,
    before_etag: String,
    before_sha256: String,
    replacement_sha256: String,
    owner: String,
    basis: String,
    remote_archive_mutations: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeleteIntent {
    schema: String,
    plan: Bound,
    bucket: String,
    epoch: u64,
    key: String,
    fallback_completion: Bound,
    raw_status: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_intent: Option<Bound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_before: Option<Bound>,
    archive_receipt: Bound,
    archive_sha256: String,
    archive_etag: String,
    object_etag: String,
    status: EpochStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeletionReceipt {
    schema: String,
    intent: Bound,
    binding: DeleteIntent,
    conditional_delete_request_sent_in_this_invocation: bool,
    recovered_absence_from_matching_durable_intent: bool,
    authenticated_ready_pair_before: bool,
    authenticated_status_absent_after: bool,
    authenticated_ready_pair_after: bool,
    verified_unix_seconds: u64,
}

fn sha(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn quoted_etag(value: &str) -> Result<&str> {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .context("fallback status ETag must retain original quotes")?;
    ensure!(
        inner.len() == 32
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid fallback status ETag"
    );
    Ok(inner)
}

fn bound_bytes(bound: &Bound, limit: u64, label: &str) -> Result<Vec<u8>> {
    ensure!(
        bound.path.is_absolute()
            && bound.path.canonicalize()? == bound.path
            && digest_valid(&bound.sha256),
        "invalid bound {label} path or digest"
    );
    let bytes = read_stable_bounded(&bound.path, limit, label)?;
    ensure!(sha(&bytes) == bound.sha256, "changed bound {label}");
    Ok(bytes)
}

fn destination(path: &Path, epoch: u64, kind: &str, private_root: &Path) -> Result<()> {
    let expected = format!("epoch-{epoch}.fallback-ready-status-{kind}.json");
    ensure!(
        path.is_absolute() && path.file_name() == Some(std::ffi::OsStr::new(&expected)),
        "invalid fallback deletion evidence filename"
    );
    let parent = path.parent().context("deletion evidence lacks parent")?;
    ensure!(
        parent.canonicalize()? == parent && parent.starts_with(private_root),
        "deletion evidence parent is not canonical private state"
    );
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.permissions().mode() & 0o077 == 0,
        "deletion evidence parent is not root-private"
    );
    Ok(())
}

fn validate_anza_completion(
    completion: &AnzaCadenceCompletion,
    epoch: u64,
    raw_sha: &str,
    status: &EpochStatus,
) -> Result<String> {
    let etag = quoted_etag(&completion.after_etag)?;
    quoted_etag(&completion.before_etag)?;
    validate_epoch_status(status, epoch)?;
    ensure!(
        completion.epoch == epoch
            && completion.key == format!("epoch-{epoch}.epoch-status.json")
            && completion.authenticated_readback
            && completion.conditional_header == "If-Match"
            && !completion.archive_publication_authorized
            && completion.after_sha256 == raw_sha
            && &completion.after_status == status,
        "Anza cadence receipt does not bind the exact authenticated status"
    );
    Ok(etag.to_owned())
}

fn validate_anza_playback(archive: &Receipt) -> Result<()> {
    let playback = archive
        .current_reader_playback
        .as_ref()
        .context("Anza archive receipt lacks current-reader playback")?;
    let bytes = bound_bytes(
        &Bound {
            path: playback.path.clone(),
            sha256: playback.sha256.clone(),
        },
        MAX_STATUS_BYTES,
        "current-reader playback acceptance",
    )?;
    let proof: serde_json::Value = serde_json::from_slice(&bytes)?;
    let remote = &proof["remote_playback"];
    let object = &remote["object"];
    let local_report = &proof["local_playback"]["report"]["report"];
    ensure!(
        proof["schema"] == "horizon-r2-current-reader-playback-acceptance-v1"
            && proof["epoch"] == archive.epoch
            && proof["readiness_sidecar_committed"] == false
            && object["bucket"] == archive.bucket
            && object["key"] == archive.archive_key
            && object["etag"] == archive.archive_etag
            && object["length"] == archive.archive_length
            && object["sha256"] == archive.archive_sha256
            && proof["local_playback"]["process_exit_code"] == 0
            && remote["playback"]["process_exit_code"] == 0
            && local_report.is_object()
            && local_report == &remote["playback"]["report"]["report"],
        "Anza archive lacks matching local and pinned public playback"
    );
    Ok(())
}

fn validate_completion(
    completion: &FallbackCompletion,
    epoch: u64,
    raw_sha: &str,
    status: &EpochStatus,
) -> Result<String> {
    let key = format!("epoch-{epoch}.epoch-status.json");
    let etag = quoted_etag(&completion.after_etag)?;
    quoted_etag(&completion.before_etag)?;
    ensure!(
        completion.schema == COMPLETION_SCHEMA
            && completion.epoch == epoch
            && completion.key == key
            && completion.authenticated_exact_byte_readback
            && completion.conditional_header == "If-Match"
            && !completion.archive_or_sidecar_mutation
            && digest_valid(&completion.before_sha256)
            && completion.after_sha256 == raw_sha
            && completion.sampled_at_utc == status.sampled_at_utc
            && completion.phase == status.phase
            && matches!(
                status.phase.as_str(),
                "replay" | "verification" | "upload" | "readback"
            ),
        "fallback completion does not bind the exact authenticated status"
    );
    validate_epoch_status(status, epoch)?;
    Ok(etag.to_owned())
}

fn validate_operator_completion(
    completion: &OperatorCompletion,
    intent: &OperatorIntent,
    before_raw: &[u8],
    epoch: u64,
    raw_sha: &str,
    status: &EpochStatus,
) -> Result<String> {
    let key = format!("epoch-{epoch}.epoch-status.json");
    let etag = quoted_etag(&completion.new_etag)?;
    quoted_etag(&completion.before_etag)?;
    let before: EpochStatus = serde_json::from_slice(before_raw)?;
    validate_epoch_status(&before, epoch)?;
    validate_epoch_status(status, epoch)?;
    ensure!(
        completion.epoch == epoch
            && completion.key == key
            && intent.epoch == epoch
            && intent.key == key
            && completion.before_etag == intent.before_etag
            && completion.new_sha256 == raw_sha
            && intent.replacement_sha256 == raw_sha
            && intent.before_sha256 == sha(before_raw)
            && completion.sampled_at_utc == status.sampled_at_utc
            && before.sampled_at_utc < status.sampled_at_utc
            && completion.owner == intent.owner
            && !completion.owner.is_empty()
            && !intent.basis.is_empty()
            && completion.authenticated_exact_byte_readback
            && !completion.archive_or_sidecar_mutation
            && !intent.remote_archive_mutations
            && matches!(
                status.phase.as_str(),
                "replay" | "verification" | "upload" | "readback"
            ),
        "operator fallback completion does not bind the exact status publication"
    );
    Ok(etag.to_owned())
}

fn binding(plan: &Plan, plan_bound: &Bound) -> Result<(DeleteIntent, Receipt, Vec<u8>)> {
    let anza = plan.schema == ANZA_PLAN_SCHEMA;
    let private_root = if anza {
        ensure!(
            matches!(plan.epoch, 145 | 199)
                && plan.operator_intent.is_none()
                && plan.operator_before.is_none(),
            "invalid Anza cadence status deletion plan"
        );
        Path::new("/home/sol/.jetstreamer-private")
    } else {
        ensure!(
            plan.schema == PLAN_SCHEMA && (201..=300).contains(&plan.epoch),
            "invalid Foundation fallback status deletion plan"
        );
        Path::new("/home/ubuntu/.jetstreamer-private")
    };
    ensure!(
        plan.status_delete_authorized && !plan.archive_or_sidecar_mutations,
        "invalid fallback ready deletion plan"
    );
    destination(
        &plan.deletion_intent,
        plan.epoch,
        "delete-intent",
        private_root,
    )?;
    destination(&plan.deletion_receipt, plan.epoch, "deletion", private_root)?;
    ensure!(
        plan.deletion_intent.parent() == plan.deletion_receipt.parent(),
        "fallback deletion evidence must share a private parent"
    );
    let completion_raw = bound_bytes(
        &plan.fallback_completion,
        MAX_STATUS_BYTES,
        "fallback completion",
    )?;
    let raw_status = bound_bytes(&plan.raw_status, MAX_STATUS_BYTES, "raw fallback status")?;
    let status: EpochStatus = serde_json::from_slice(&raw_status)?;
    let object_etag = if anza {
        let completion = serde_json::from_slice(&completion_raw)?;
        validate_anza_completion(&completion, plan.epoch, &sha(&raw_status), &status)?
    } else if plan.operator_intent.is_some() || plan.operator_before.is_some() {
        let operator_intent = plan
            .operator_intent
            .as_ref()
            .context("missing operator intent")?;
        let operator_before = plan
            .operator_before
            .as_ref()
            .context("missing operator before")?;
        let original: OperatorIntent = serde_json::from_slice(&bound_bytes(
            operator_intent,
            MAX_STATUS_BYTES,
            "operator publication intent",
        )?)?;
        let before_raw = bound_bytes(operator_before, MAX_STATUS_BYTES, "operator prior status")?;
        let completion: OperatorCompletion = serde_json::from_slice(&completion_raw)?;
        validate_operator_completion(
            &completion,
            &original,
            &before_raw,
            plan.epoch,
            &sha(&raw_status),
            &status,
        )?
    } else {
        let completion: FallbackCompletion = serde_json::from_slice(&completion_raw)?;
        validate_completion(&completion, plan.epoch, &sha(&raw_status), &status)?
    };
    let receipt_raw = bound_bytes(
        &plan.archive_receipt,
        MAX_STATUS_BYTES,
        "R2 archive receipt",
    )?;
    let archive: Receipt = serde_json::from_slice(&receipt_raw)?;
    let parent = plan
        .archive_receipt
        .path
        .parent()
        .context("archive receipt lacks parent")?;
    ensure!(
        plan.archive_receipt.path == receipt_path(parent, plan.epoch)
            && archive == read_restore_receipt(parent, &plan.bucket, plan.epoch)?
            && (archive.remote_sha256_readback || archive.r2_composite_sha256.is_some()),
        "archive receipt changed or lacks whole-object proof"
    );
    if anza {
        ensure!(
            archive.remote_sha256_readback && status.jet_size_bytes == archive.archive_length,
            "Anza archive lacks whole-object readback or differs from the status length"
        );
        validate_anza_playback(&archive)?;
    }
    let intent = DeleteIntent {
        schema: INTENT_SCHEMA.into(),
        plan: plan_bound.clone(),
        bucket: plan.bucket.clone(),
        epoch: plan.epoch,
        key: format!("epoch-{}.epoch-status.json", plan.epoch),
        fallback_completion: plan.fallback_completion.clone(),
        raw_status: plan.raw_status.clone(),
        operator_intent: plan.operator_intent.clone(),
        operator_before: plan.operator_before.clone(),
        archive_receipt: plan.archive_receipt.clone(),
        archive_sha256: archive.archive_sha256.clone(),
        archive_etag: archive.archive_etag.clone(),
        object_etag,
        status,
    };
    Ok((intent, archive, raw_status))
}

fn existing<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(serde_json::from_slice(&read_stable_bounded(
            path,
            MAX_STATUS_BYTES,
            "fallback deletion evidence",
        )?)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn persist<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().context("evidence lacks parent")?)?.sync_all()?;
    Ok(())
}

fn matching_status(current: &MutableRemoteObject, intent: &DeleteIntent, raw: &[u8]) -> Result<()> {
    ensure!(
        current.etag == intent.object_etag && current.bytes == raw,
        "current status differs from the exact fallback publication"
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 status-delete-fallback-ready PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fallback ready deletion requires root"
    );
    let mut executable = File::open("/proc/self/exe")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    ensure!(
        hex_lower(&hasher.finalize()) == args[6],
        "executable SHA-256 mismatch"
    );
    let plan_bound = Bound {
        path: PathBuf::from(&args[2]),
        sha256: args[4].clone(),
    };
    let plan_raw = bound_bytes(&plan_bound, MAX_STATUS_BYTES, "fallback deletion plan")?;
    let plan: Plan = serde_json::from_slice(&plan_raw)?;
    let (intent, archive, raw_status) = binding(&plan, &plan_bound)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == plan.bucket,
        "R2 environment names another bucket"
    );
    let s3 = s3_client(&r2);
    validate_authenticated_ready_pair(&s3, &r2.bucket, &archive).await?;
    let current = get_mutable_object(&s3, &r2.bucket, &intent.key).await?;
    let prior_intent = existing::<DeleteIntent>(&plan.deletion_intent)?;
    if let Some(before) = &prior_intent {
        ensure!(
            before == &intent,
            "existing fallback deletion intent differs"
        );
    }
    if let Some(current) = &current {
        matching_status(current, &intent, &raw_status)?;
    } else {
        ensure!(
            prior_intent.is_some(),
            "status absent without matching durable deletion intent"
        );
    }
    if args.len() == 8 {
        println!(
            "{}",
            serde_json::json!({"epoch":plan.epoch,"authenticated_ready_pair":true,
            "status_matches_fallback_publication":current.is_some(),"remote_mutations":false})
        );
        return Ok(());
    }
    if let Some(done) = existing::<DeletionReceipt>(&plan.deletion_receipt)? {
        ensure!(
            current.is_none()
                && done.schema == DELETION_SCHEMA
                && done.binding == intent
                && done.authenticated_ready_pair_before
                && done.authenticated_status_absent_after
                && done.authenticated_ready_pair_after,
            "existing fallback deletion receipt differs or status reappeared"
        );
        let intent_raw = bound_bytes(&done.intent, MAX_STATUS_BYTES, "deletion intent")?;
        ensure!(
            done.intent.path == plan.deletion_intent
                && serde_json::from_slice::<DeleteIntent>(&intent_raw)? == intent,
            "existing deletion receipt binds another intent"
        );
        println!("{}", plan.deletion_receipt.display());
        return Ok(());
    }
    if prior_intent.is_none() {
        persist(&plan.deletion_intent, &intent)?;
    }
    let intent_raw =
        read_stable_bounded(&plan.deletion_intent, MAX_STATUS_BYTES, "deletion intent")?;
    ensure!(
        serde_json::from_slice::<DeleteIntent>(&intent_raw)? == intent,
        "durable intent changed"
    );
    ensure!(
        bound_bytes(&plan_bound, MAX_STATUS_BYTES, "fallback deletion plan")? == plan_raw,
        "fallback deletion plan changed before request"
    );
    let (rechecked, rechecked_archive, rechecked_raw) = binding(&plan, &plan_bound)?;
    ensure!(
        rechecked == intent && rechecked_archive == archive && rechecked_raw == raw_status,
        "fallback or archive evidence changed before request"
    );
    if current.is_some() {
        conditional_delete_epoch_status(&s3, &r2.bucket, plan.epoch, &intent.object_etag).await?;
    }
    ensure!(
        get_mutable_object(&s3, &r2.bucket, &intent.key)
            .await?
            .is_none(),
        "fallback status remains after conditional deletion"
    );
    validate_authenticated_ready_pair(&s3, &r2.bucket, &archive).await?;
    ensure!(
        bound_bytes(&plan_bound, MAX_STATUS_BYTES, "fallback deletion plan")? == plan_raw,
        "fallback deletion plan changed after request"
    );
    let intent_bound = Bound {
        path: plan.deletion_intent.clone(),
        sha256: sha(&intent_raw),
    };
    persist(
        &plan.deletion_receipt,
        &DeletionReceipt {
            schema: DELETION_SCHEMA.into(),
            intent: intent_bound,
            binding: intent,
            conditional_delete_request_sent_in_this_invocation: current.is_some(),
            recovered_absence_from_matching_durable_intent: current.is_none(),
            authenticated_ready_pair_before: true,
            authenticated_status_absent_after: true,
            authenticated_ready_pair_after: true,
            verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        },
    )?;
    println!("{}", plan.deletion_receipt.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion() -> FallbackCompletion {
        FallbackCompletion {
            schema: COMPLETION_SCHEMA.into(),
            epoch: 239,
            key: "epoch-239.epoch-status.json".into(),
            before_etag: format!("\"{}\"", "a".repeat(32)),
            after_etag: format!("\"{}\"", "b".repeat(32)),
            before_sha256: "a".repeat(64),
            after_sha256: "c".repeat(64),
            sampled_at_utc: "2026-11-17T12:28:28Z".into(),
            phase: "readback".into(),
            authenticated_exact_byte_readback: true,
            conditional_header: "If-Match".into(),
            archive_or_sidecar_mutation: false,
        }
    }
    fn status() -> EpochStatus {
        EpochStatus {
            epoch: 239,
            jet_size_bytes: 161,
            elapsed_execution_millis: 10,
            estimated_remaining_millis: 20,
            sampled_at_utc: "2026-11-17T12:28:28Z".into(),
            phase: "readback".into(),
        }
    }
    #[test]
    fn binds_raw_fallback_publication() {
        assert_eq!(
            validate_completion(&completion(), 239, &"c".repeat(64), &status()).unwrap(),
            "b".repeat(32)
        );
        let mut changed = completion();
        changed.authenticated_exact_byte_readback = false;
        assert!(validate_completion(&changed, 239, &"c".repeat(64), &status()).is_err());
        changed = completion();
        changed.phase = "upload".into();
        assert!(validate_completion(&changed, 239, &"c".repeat(64), &status()).is_err());
        assert!(validate_completion(&completion(), 239, &"d".repeat(64), &status()).is_err());
    }

    #[test]
    fn binds_anza_cadence_receipt_to_expected_bytes_and_status() {
        let status = EpochStatus {
            epoch: 199,
            phase: "verification".into(),
            ..status()
        };
        let digest = "c".repeat(64);
        let mut receipt = AnzaCadenceCompletion {
            epoch: 199,
            key: "epoch-199.epoch-status.json".into(),
            before_etag: format!("\"{}\"", "a".repeat(32)),
            after_etag: format!("\"{}\"", "b".repeat(32)),
            after_sha256: digest.clone(),
            after_status: status.clone(),
            authenticated_readback: true,
            conditional_header: "If-Match".into(),
            archive_publication_authorized: false,
        };
        assert_eq!(
            validate_anza_completion(&receipt, 199, &digest, &status).unwrap(),
            "b".repeat(32)
        );
        assert!(validate_anza_completion(&receipt, 199, &"d".repeat(64), &status).is_err());
        receipt.after_status.jet_size_bytes += 1;
        assert!(validate_anza_completion(&receipt, 199, &digest, &status).is_err());
        receipt.after_status = status.clone();
        receipt.key = "epoch-199.jet.sha256".into();
        assert!(validate_anza_completion(&receipt, 199, &digest, &status).is_err());
    }

    #[test]
    fn binds_operator_fallback_and_rejects_changed_evidence() {
        let before = EpochStatus {
            sampled_at_utc: "2026-11-17T12:00:00Z".into(),
            ..status()
        };
        let before_raw = serde_json::to_vec(&before).unwrap();
        let after = status();
        let raw_sha = "c".repeat(64);
        let mut completion = OperatorCompletion {
            epoch: 239,
            key: "epoch-239.epoch-status.json".into(),
            before_etag: format!("\"{}\"", "a".repeat(32)),
            new_etag: format!("\"{}\"", "b".repeat(32)),
            new_sha256: raw_sha.clone(),
            sampled_at_utc: after.sampled_at_utc.clone(),
            owner: "/root".into(),
            authenticated_exact_byte_readback: true,
            archive_or_sidecar_mutation: false,
        };
        let mut intent = OperatorIntent {
            epoch: 239,
            key: completion.key.clone(),
            before_etag: completion.before_etag.clone(),
            before_sha256: sha(&before_raw),
            replacement_sha256: raw_sha.clone(),
            owner: completion.owner.clone(),
            basis: "measured upload progress".into(),
            remote_archive_mutations: false,
        };
        assert_eq!(
            validate_operator_completion(&completion, &intent, &before_raw, 239, &raw_sha, &after)
                .unwrap(),
            "b".repeat(32)
        );
        intent.before_sha256 = "d".repeat(64);
        assert!(
            validate_operator_completion(&completion, &intent, &before_raw, 239, &raw_sha, &after)
                .is_err()
        );
        intent.before_sha256 = sha(&before_raw);
        completion.authenticated_exact_byte_readback = false;
        assert!(
            validate_operator_completion(&completion, &intent, &before_raw, 239, &raw_sha, &after)
                .is_err()
        );
    }
    #[test]
    fn status_race_rejects_changed_bytes_or_etag() {
        let intent = DeleteIntent {
            schema: INTENT_SCHEMA.into(),
            plan: Bound {
                path: "/a".into(),
                sha256: "a".repeat(64),
            },
            bucket: "bucket".into(),
            epoch: 239,
            key: "epoch-239.epoch-status.json".into(),
            fallback_completion: Bound {
                path: "/b".into(),
                sha256: "b".repeat(64),
            },
            raw_status: Bound {
                path: "/c".into(),
                sha256: "c".repeat(64),
            },
            operator_intent: None,
            operator_before: None,
            archive_receipt: Bound {
                path: "/d".into(),
                sha256: "d".repeat(64),
            },
            archive_sha256: "e".repeat(64),
            archive_etag: "etag".into(),
            object_etag: "b".repeat(32),
            status: status(),
        };
        let good = MutableRemoteObject {
            bytes: b"raw".to_vec(),
            etag: "b".repeat(32),
        };
        assert!(matching_status(&good, &intent, b"raw").is_ok());
        assert!(matching_status(&good, &intent, b"changed").is_err());
        let other = MutableRemoteObject {
            bytes: b"raw".to_vec(),
            etag: "a".repeat(32),
        };
        assert!(matching_status(&other, &intent, b"raw").is_err());
    }
}
