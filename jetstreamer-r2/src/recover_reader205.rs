//! Read-only finalization of epoch205's completed playback after exact source review.
//! Only HEAD and GET-sidecar reach S3; no archive upload, sidecar PUT, or retirement.
use super::*;
use current_reader::recovery205 as proof;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    helper: current_reader::Bound,
    source_publication: current_reader::Bound,
    original_journal: current_reader::Bound,
    bucket: String,
    output_directory: PathBuf,
    minimum_free_bytes: u64,
    maximum_elapsed_seconds: u64,
}
fn remote_value(r: &RemoteArchive) -> serde_json::Value {
    serde_json::json!({"length":r.length,"etag":r.etag,"metadata_sha256":r.metadata_sha256,
    "composite_sha256":r.composite_sha256,"checksum_type":r.checksum_type.as_ref().map(|v|v.as_str()),
    "multipart_part_size":r.multipart_part_size})
}
fn remote_proof(r: &RemoteArchive, p: &LocalProof) -> Result<()> {
    ensure!(
        r.length == proof::LENGTH && p.sha256_hex == proof::SHA && r.etag == p.multipart_etag,
        "recovery remote bytes/ETag mismatch"
    );
    if let Some(v) = &r.metadata_sha256 {
        ensure!(v == proof::SHA, "remote SHA metadata differs");
    }
    let part = r
        .multipart_part_size
        .context("original route requires remote part-size metadata")?;
    ensure!(
        (5u64 * 1024 * 1024..=5u64 * 1024 * 1024 * 1024).contains(&part),
        "remote part-size bounds"
    );
    if let Some(v) = &r.composite_sha256 {
        ensure!(
            r.checksum_type == Some(ChecksumType::Composite)
                && composite_checksum_matches(v, &p.composite_sha256, proof::LENGTH.div_ceil(part)),
            "remote composite checksum differs"
        );
    }
    Ok(())
}
fn output_directory(p: &Path) -> Result<()> {
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && p.starts_with("/home/ubuntu/.jetstreamer-private")
            && p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("reader205-recovery-")),
        "recovery output scope"
    );
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700
            && fs::read_dir(p)?.next().is_none(),
        "new root0700 empty recovery directory required"
    );
    Ok(())
}
fn capacity(path: &Path, floor: u64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), &mut s) } == 0,
        "recovery filesystem capacity"
    );
    ensure!(
        u128::from(s.f_bavail) * u128::from(s.f_frsize) >= u128::from(floor) + 16 * 1024 * 1024,
        "recovery metadata crosses admitted floor"
    );
    Ok(())
}
fn body_hash(path: &Path, part: u64, label: &str) -> Result<LocalProof> {
    let id = regular_identity(path)?;
    ensure!(id.length == proof::LENGTH, "recovery body length");
    let mut last = 0u64;
    hash_and_etag_observed(path, id, part, |n| {
        if n - last >= 8 * 1024 * 1024 * 1024 || n == proof::LENGTH {
            eprintln!(
                "epoch205 recovery {label}: hashed {n}/{} bytes",
                proof::LENGTH
            );
            last = n;
        }
    })
}
pub async fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "epoch205 recovery requires root"
    );
    let args: Vec<String> = env::args().collect();
    ensure!(
        args.len() == 5 && args[1] == "recover-reader205-finalization",
        "usage: jetstreamer-r2 recover-reader205-finalization PLAN PLAN_SHA SELF_SHA"
    );
    let binding = current_reader::Bound {
        path: args[2].clone().into(),
        sha256: args[3].clone(),
    };
    let request: Request = serde_json::from_value(proof::load_bound(&binding)?)?;
    ensure!(
        request.schema == "horizon205-reader-finalization-recovery-plan-v1"
            && request.helper.sha256 == args[4]
            && request.bucket == "solana-archive-with-accounts-data"
            && request.minimum_free_bytes >= 3_000_000_000_000
            && (60..=7200).contains(&request.maximum_elapsed_seconds)
            && fs::read_link("/proc/self/exe")? == request.helper.path,
        "recovery plan/self scope"
    );
    proof::check_bound(&request.helper)?;
    ensure!(
        format!("{:x}", Sha256::digest(fs::read("/proc/self/exe")?)) == args[4],
        "executing recovery image changed"
    );
    output_directory(&request.output_directory)?;
    capacity(&request.output_directory, request.minimum_free_bytes)?;
    let started = Instant::now();
    let journal = request.original_journal.clone();
    let evidence = tokio::task::spawn_blocking(move || proof::prepare(journal)).await??;
    // Reject an unpublished/unqualified recovery image before any large read.
    let source = request.source_publication.clone();
    let helper = request.helper.clone();
    let evidence = tokio::task::spawn_blocking(move || -> Result<_> {
        evidence.final_source(&source, &helper)?;
        Ok(evidence)
    })
    .await??;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == request.bucket, "recovery bucket differs");
    let client = s3_client(&r2);
    let archive_key = "epoch-205.jet";
    let sidecar_key = "epoch-205.jet.sha256";
    let before = head_archive(&client, &r2.bucket, archive_key)
        .await?
        .context("recovery archive missing")?;
    let part = before
        .multipart_part_size
        .context("original audit required multipart-part-size metadata")?;
    ensure!(
        (5u64 * 1024 * 1024..=5u64 * 1024 * 1024 * 1024).contains(&part)
            && before.length == proof::LENGTH,
        "recovery remote bounds"
    );
    let local = read_local_archive(Path::new(proof::LOCAL), proof::EPOCH)?;
    ensure!(
        local.sha256_hex == proof::SHA && local.length == proof::LENGTH,
        "original staged archive differs"
    );
    let canonical = format!("{}  epoch-205.jet\n", proof::SHA).into_bytes();
    ensure!(
        local.sidecar == canonical
            && remote_sidecar(&client, &r2.bucket, sidecar_key)
                .await?
                .as_deref()
                == Some(canonical.as_slice()),
        "recovery canonical sidecar mismatch"
    );
    let local_path = local.archive_path.clone();
    let (readback_hash, local_hash) = tokio::task::spawn_blocking(move || -> Result<_> {
        let readback_hash = body_hash(&proof::readback(), part, "original authenticated readback")?;
        let local_hash = body_hash(&local_path, part, "original staged archive")?;
        Ok((readback_hash, local_hash))
    })
    .await??;
    remote_proof(&before, &readback_hash)?;
    remote_proof(&before, &local_hash)?;
    ensure!(
        readback_hash.composite_sha256 == local_hash.composite_sha256,
        "staged/readback bytes differ"
    );
    revalidate_local(&local)?;
    let source = request.source_publication.clone();
    let helper = request.helper.clone();
    let (evidence, source_proof) = tokio::task::spawn_blocking(move || -> Result<_> {
        let source = evidence.final_source(&source, &helper)?;
        Ok((evidence, source))
    })
    .await??;
    // The final pair observation follows the fresh branch/source gate and both full hashes.
    let after = head_archive(&client, &r2.bucket, archive_key)
        .await?
        .context("recovery archive disappeared")?;
    remote_proof(&after, &readback_hash)?;
    ensure!(
        remote_value(&after) == remote_value(&before)
            && remote_sidecar(&client, &r2.bucket, sidecar_key)
                .await?
                .as_deref()
                == Some(canonical.as_slice()),
        "remote pair changed during recovery"
    );
    revalidate_local(&local)?;
    evidence.recheck()?;
    ensure!(
        started.elapsed().as_secs() <= request.maximum_elapsed_seconds,
        "recovery exceeded accepted operation bound"
    );
    capacity(&request.output_directory, request.minimum_free_bytes)?;
    let object = current_reader::RemoteObject {
        bucket: r2.bucket.clone(),
        key: archive_key.into(),
        etag: after.etag.clone(),
        length: proof::LENGTH,
        sha256: proof::SHA.into(),
    };
    let native = serde_json::json!({"authenticated_endpoint":r2.endpoint,"authenticated_head_before":remote_value(&before),"authenticated_head_after":remote_value(&after),"authenticated_sidecar_key":sidecar_key,"canonical_sidecar_sha256":format!("{:x}",Sha256::digest(&canonical)),"whole_readback_sha256":readback_hash.sha256_hex,"whole_staged_archive_sha256":local_hash.sha256_hex,"readback_multipart_etag":readback_hash.multipart_etag,"readback_composite_sha256":readback_hash.composite_sha256,"multipart_part_size":part,"remote_object_identity_reconstructed_from_retained_bytes_and_fresh_authenticated_head":true,"historical_in_memory_etag_claimed":false,"original_local_revalidation_repeated":true,"recovery_elapsed_seconds":started.elapsed().as_secs()});
    let acceptance = evidence.acceptance(source_proof, object, native, &binding)?;
    let acceptance_binding = proof::write_bound(
        &request
            .output_directory
            .join("recovered-audit-acceptance.json"),
        &acceptance,
    )?;
    // New private audit receipt only. Never overwrite the historical receipt or public pair.
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.into(),
        bucket: r2.bucket,
        epoch: proof::EPOCH,
        archive_key: archive_key.into(),
        checksum_key: sidecar_key.into(),
        archive_length: proof::LENGTH,
        archive_sha256: proof::SHA.into(),
        archive_etag: after.etag,
        r2_composite_sha256: after.composite_sha256,
        remote_sha256_readback: true,
        current_reader_playback: Some(acceptance_binding),
        multipart_part_size: part,
        verified_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    proof::write_bound(
        &request.output_directory.join("epoch-205.r2.json"),
        &serde_json::to_value(receipt)?,
    )?;
    eprintln!(
        "epoch205 recovered audit acceptance written to {}; original run remains failed; no remote or retirement operation performed",
        request.output_directory.display()
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_remote_proof_rejects_changed_sha_etag_size_part_policy_and_checksum() {
        let p = LocalProof {
            sha256_hex: proof::SHA.into(),
            multipart_etag: "a-2".into(),
            composite_sha256: "checksum".into(),
        };
        let make = || RemoteArchive {
            length: proof::LENGTH,
            etag: p.multipart_etag.clone(),
            metadata_sha256: Some(proof::SHA.into()),
            composite_sha256: None,
            checksum_type: None,
            multipart_part_size: Some(64 * 1024 * 1024),
        };
        remote_proof(&make(), &p).unwrap();
        let mut r = make();
        r.etag = "changed".into();
        assert!(remote_proof(&r, &p).is_err());
        let mut r = make();
        r.length -= 1;
        assert!(remote_proof(&r, &p).is_err());
        let mut r = make();
        r.multipart_part_size = None;
        assert!(remote_proof(&r, &p).is_err());
        let mut r = make();
        r.multipart_part_size = Some(1);
        assert!(remote_proof(&r, &p).is_err());
        let mut r = make();
        r.metadata_sha256 = Some("b".repeat(64));
        assert!(remote_proof(&r, &p).is_err());
        let mut r = make();
        r.composite_sha256 = Some("wrong".into());
        r.checksum_type = Some(ChecksumType::Composite);
        assert!(remote_proof(&r, &p).is_err());
    }
    #[test]
    fn recovery_route_has_no_remote_write_or_retirement_calls() {
        let source = include_str!("recover_reader205.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "put_object(",
            "delete_object(",
            "upload_archive(",
            "put_sidecar(",
            "retire_local(",
            "remove_file(",
            "write_receipt(",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden recovery action {forbidden}"
            );
        }
    }
}
