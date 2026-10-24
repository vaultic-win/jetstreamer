//! Read-only restoration of a ready pair for a private resource-size audit.
//! This is deliberately not a producer completion receipt or a publication gate.
use super::*;
use serde_json::json;
use std::{ffi::CString, os::unix::ffi::OsStrExt};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-private-resource-audit-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-private-resource-audit-receipt-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    bucket: String,
    epoch: u64,
    archive_length: u64,
    archive_sha256: String,
    archive_etag: String,
    multipart_part_size: u64,
    concurrency: usize,
    directory: PathBuf,
    receipt: PathBuf,
    // Transfer-only bound, not the campaign's canonical century floor.
    minimum_free_after_restore_bytes: u64,
    production_completion_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical private directory"
    );
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "audit directory must be root-owned and owner-only"
    );
    Ok(())
}

fn free_bytes(path: &Path) -> Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL-terminated; stat points to correctly sized writable storage.
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful statvfs initialized the structure.
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-space overflow")
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "invalid resource audit schema");
    ensure!(
        !plan.production_completion_authorized
            && !plan.publication_authorized
            && !plan.remote_mutations
            && !plan.r2_mutations,
        "audit cannot grant mutation or completion authority"
    );
    ensure!(
        (200..=300).contains(&plan.epoch)
            && plan.archive_length > 0
            && is_lower_hex(&plan.archive_sha256, 64)
            && plan.multipart_part_size >= 5 * 1024 * 1024
            && plan.multipart_part_size <= 5 * 1024 * 1024 * 1024
            && (1..=16).contains(&plan.concurrency)
            && plan.minimum_free_after_restore_bytes > 0,
        "invalid audit bounds"
    );
    ensure!(
        plan.receipt.file_name().is_some()
            && plan.receipt.parent() == Some(plan.directory.as_path()),
        "receipt must be a direct private member"
    );
    ensure!(
        plan.receipt.file_name().unwrap() == "resource-audit.json",
        "noncanonical audit receipt name"
    );
    Ok(())
}

fn proof_receipt(plan: &Plan) -> Receipt {
    // In-memory adapter only. Never serialize this as a producer/R2 completion receipt.
    Receipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        bucket: plan.bucket.clone(),
        epoch: plan.epoch,
        archive_key: format!("epoch-{}.jet", plan.epoch),
        checksum_key: format!("epoch-{}.jet.sha256", plan.epoch),
        archive_length: plan.archive_length,
        archive_sha256: plan.archive_sha256.clone(),
        archive_etag: plan.archive_etag.clone(),
        r2_composite_sha256: None,
        remote_sha256_readback: true,
        multipart_part_size: plan.multipart_part_size,
        verified_unix_seconds: 0,
    }
}

fn validate_head(remote: &RemoteArchive, proof: &Receipt) -> Result<()> {
    validate_remote_against_receipt(remote, proof)?;
    ensure!(
        remote.metadata_sha256.as_deref() == Some(proof.archive_sha256.as_str()),
        "audit requires bound archive SHA-256 metadata"
    );
    ensure!(
        remote.multipart_part_size == Some(proof.multipart_part_size),
        "audit requires exact remote multipart part size"
    );
    ensure!(
        remote.composite_sha256 == proof.r2_composite_sha256,
        "audit composite checksum presence changed"
    );
    Ok(())
}

fn validate_audit_archive(path: &Path, proof: &Receipt) -> Result<FileIdentity> {
    let identity = regular_identity(path)?;
    ensure!(
        identity.length == proof.archive_length,
        "audit local length mismatch"
    );
    let local = hash_and_etag(path, identity, proof.multipart_part_size)?;
    ensure!(
        local.sha256_hex == proof.archive_sha256 && local.multipart_etag == proof.archive_etag,
        "audit local SHA-256 or ETag mismatch"
    );
    if let Some(expected) = &proof.r2_composite_sha256 {
        ensure!(
            composite_checksum_matches(
                expected,
                &local.composite_sha256,
                proof.archive_length.div_ceil(proof.multipart_part_size)
            ),
            "audit composite checksum mismatch"
        );
    }
    Ok(identity)
}

struct GuardedWriter<'a> {
    file: &'a mut File,
    directory: &'a Path,
    minimum: u64,
}

impl Write for GuardedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = free_bytes(self.directory).map_err(std::io::Error::other)?;
        if available < self.minimum.saturating_add(bytes.len() as u64) {
            return Err(std::io::Error::other(
                "private audit transfer reserve reached",
            ));
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

async fn validate_pair(client: &Client, r2: &R2Config, proof: &Receipt) -> Result<()> {
    let head = head_archive(client, &r2.bucket, &proof.archive_key)
        .await?
        .context("audit archive missing")?;
    validate_head(&head, proof)?;
    ensure!(
        remote_sidecar(client, &r2.bucket, &proof.checksum_key)
            .await?
            .as_deref()
            == Some(canonical_sidecar(proof).as_slice()),
        "audit remote sidecar mismatch"
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(2).collect();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: private-resource-audit PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private resource audit requires root"
    );
    ensure!(
        is_lower_hex(&args[2], 64) && is_lower_hex(&args[4], 64),
        "invalid bound SHA-256"
    );
    let mut executable = File::open("/proc/self/exe")?;
    let mut digest = Sha256::new();
    std::io::copy(&mut executable, &mut digest)?;
    ensure!(
        hex_lower(&digest.finalize()) == args[4],
        "audit executable hash mismatch"
    );
    let plan_path = Path::new(&args[0]);
    ensure!(
        plan_path.is_absolute() && fs::canonicalize(plan_path)? == plan_path,
        "noncanonical audit plan"
    );
    let meta = fs::symlink_metadata(plan_path)?;
    ensure!(
        meta.uid() == 0 && meta.mode() & 0o222 == 0 && meta.nlink() == 1,
        "audit plan must be immutable, singly linked and root-owned"
    );
    let bytes = read_stable_bounded(plan_path, 64 * 1024, "audit plan")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == args[2],
        "audit plan hash mismatch"
    );
    let plan: Plan = serde_json::from_slice(&bytes)?;
    validate_plan(&plan)?;
    private_directory(&plan.directory)?;
    ensure!(
        !plan.receipt.try_exists()?,
        "audit receipt already exists; inspect retained evidence"
    );
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == plan.bucket, "audit bucket mismatch");
    let client = s3_client(&r2);
    let mut proof = proof_receipt(&plan);
    let initial_head = head_archive(&client, &r2.bucket, &proof.archive_key)
        .await?
        .context("audit archive missing")?;
    if initial_head.composite_sha256.is_some() {
        ensure!(
            initial_head.checksum_type == Some(ChecksumType::Composite),
            "audit native checksum is not composite"
        );
        proof.r2_composite_sha256 = initial_head.composite_sha256.clone();
    }
    validate_head(&initial_head, &proof)?;
    validate_pair(&client, &r2, &proof).await?;
    let archive = plan.directory.join(&proof.archive_key);
    let sidecar = plan.directory.join(&proof.checksum_key);
    if !archive.try_exists()? {
        ensure!(
            free_bytes(&plan.directory)?
                >= plan
                    .minimum_free_after_restore_bytes
                    .checked_add(plan.archive_length)
                    .context("audit space overflow")?,
            "insufficient audit reserve"
        );
        eprintln!(
            "epoch {}: private resource audit restoring {} bytes; no remote mutation",
            plan.epoch, plan.archive_length
        );
        let mut temporary = tempfile::Builder::new()
            .prefix(".resource-audit-")
            .tempfile_in(&plan.directory)?;
        let mut writer = GuardedWriter {
            file: temporary.as_file_mut(),
            directory: &plan.directory,
            minimum: plan.minimum_free_after_restore_bytes,
        };
        read_remote_sha256_resumable(
            &client,
            RemoteReadSpec {
                bucket: &r2.bucket,
                key: &proof.archive_key,
                etag: &proof.archive_etag,
                expected_length: proof.archive_length,
                expected_sha256: &proof.archive_sha256,
                concurrency: plan.concurrency,
            },
            &mut writer,
        )
        .await?;
        ensure!(
            free_bytes(&plan.directory)? >= plan.minimum_free_after_restore_bytes,
            "audit reserve eroded"
        );
        persist_noclobber(temporary, &archive)?;
        File::open(&plan.directory)?.sync_all()?;
    }
    eprintln!(
        "epoch {}: independent local audit SHA-256/ETag reread",
        plan.epoch
    );
    let identity = validate_audit_archive(&archive, &proof)?;
    validate_pair(&client, &r2, &proof).await?;
    if !sidecar.try_exists()? {
        let mut temporary = tempfile::NamedTempFile::new_in(&plan.directory)?;
        temporary.write_all(&canonical_sidecar(&proof))?;
        persist_noclobber(temporary, &sidecar)?;
        File::open(&plan.directory)?.sync_all()?;
    }
    validate_restored_sidecar(&sidecar, &canonical_sidecar(&proof))?;
    ensure!(
        regular_identity(&archive)? == identity,
        "audit archive identity changed"
    );
    let value = json!({
        "schema": RECEIPT_SCHEMA, "purpose": "century-floor-resource-audit-only",
        "bucket": plan.bucket, "epoch": plan.epoch, "archive_key": proof.archive_key,
        "checksum_key": proof.checksum_key, "archive_path": archive,
        "archive_length": plan.archive_length, "archive_sha256": plan.archive_sha256,
        "archive_etag": plan.archive_etag, "multipart_part_size": plan.multipart_part_size,
        "r2_composite_sha256": proof.r2_composite_sha256,
        "archive_device": identity.device, "archive_inode": identity.inode,
        "remote_sha256_readback": true, "local_sha256_and_etag_verified": true,
        "authenticated_ready_pair_revalidated": true,
        "plan_path": plan_path, "plan_sha256": args[2], "tool_sha256": args[4],
        "verified_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "production_completion_authorized": false, "publication_authorized": false,
        "local_retirement_authorized": false, "remote_mutations": false, "r2_mutations": false
    });
    fleet::persist(&plan.receipt, &value)?;
    eprintln!(
        "private audit restore verified: {} (full/plugin audit still required)",
        plan.receipt.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        Plan {
            schema: PLAN_SCHEMA.into(),
            bucket: "horizon".into(),
            epoch: 201,
            archive_length: 12,
            archive_sha256: "a".repeat(64),
            archive_etag: "b-1".into(),
            multipart_part_size: 64 * 1024 * 1024,
            concurrency: 2,
            directory: "/private/audit".into(),
            receipt: "/private/audit/resource-audit.json".into(),
            minimum_free_after_restore_bytes: 1,
            production_completion_authorized: false,
            publication_authorized: false,
            remote_mutations: false,
            r2_mutations: false,
        }
    }
    #[test]
    fn plan_rejects_authority_scope_and_bounds() {
        let mut p = plan();
        validate_plan(&p).unwrap();
        p.production_completion_authorized = true;
        assert!(validate_plan(&p).is_err());
        p.production_completion_authorized = false;
        p.epoch = 199;
        assert!(validate_plan(&p).is_err());
        p.epoch = 201;
        p.receipt = "/other/resource-audit.json".into();
        assert!(validate_plan(&p).is_err());
        p.receipt = "/private/audit/resource-audit.json".into();
        p.concurrency = 0;
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn requires_exact_metadata_and_part_size() {
        let p = plan();
        let proof = proof_receipt(&p);
        let mut head = RemoteArchive {
            length: 12,
            etag: p.archive_etag,
            metadata_sha256: Some(p.archive_sha256),
            composite_sha256: None,
            checksum_type: None,
            multipart_part_size: Some(p.multipart_part_size),
        };
        validate_head(&head, &proof).unwrap();
        head.multipart_part_size = None;
        assert!(validate_head(&head, &proof).is_err());
        head.multipart_part_size = Some(p.multipart_part_size);
        head.metadata_sha256 = None;
        assert!(validate_head(&head, &proof).is_err());
    }
    #[test]
    fn audit_schema_is_not_production_completion() {
        assert_ne!(proof_receipt(&plan()).schema, super::super::RECEIPT_SCHEMA);
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            receipt_path(dir.path(), 201),
            serde_json::to_vec(&proof_receipt(&plan())).unwrap(),
        )
        .unwrap();
        assert!(read_restore_receipt(dir.path(), "horizon", 201).is_err());
    }

    #[test]
    fn audit_path_has_no_remote_mutation_call_sites() {
        let source = include_str!("resource_audit.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            ".put_object(",
            ".delete_object(",
            ".create_multipart_upload(",
            ".upload_part(",
            ".complete_multipart_upload(",
            "write_receipt(",
        ] {
            assert!(
                !source.contains(forbidden),
                "unexpected audit mutation: {forbidden}"
            );
        }
    }

    #[test]
    fn audit_local_proof_rejects_wrong_sha_and_etag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-201.jet");
        fs::write(&path, b"audit sample").unwrap();
        let mut p = plan();
        let hashed = hash_and_etag(
            &path,
            regular_identity(&path).unwrap(),
            p.multipart_part_size,
        )
        .unwrap();
        p.archive_sha256 = hashed.sha256_hex;
        p.archive_etag = hashed.multipart_etag;
        let mut proof = proof_receipt(&p);
        validate_audit_archive(&path, &proof).unwrap();
        proof.archive_sha256 = "0".repeat(64);
        assert!(validate_audit_archive(&path, &proof).is_err());
        proof = proof_receipt(&p);
        proof.archive_etag = "wrong".into();
        assert!(validate_audit_archive(&path, &proof).is_err());
        proof = proof_receipt(&p);
        proof.r2_composite_sha256 = Some("wrong".into());
        assert!(validate_audit_archive(&path, &proof).is_err());
    }
    #[test]
    fn guarded_writer_fails_before_allocating_at_reserve() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = tempfile::tempfile().unwrap();
        let mut writer = GuardedWriter {
            file: &mut file,
            directory: dir.path(),
            minimum: u64::MAX,
        };
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
