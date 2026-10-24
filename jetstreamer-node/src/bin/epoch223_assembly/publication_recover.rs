//! Recovery of only this publisher's exact verified V3 bytes and root context.
//! No Bank rerun, foreign batch recovery, archive replacement or R2 operation.
use super::*;
use jetstreamer_node::{
    archive_checksum::{
        archive_batch_publication_in_progress, archive_checksum_line, rebind_validated_after_rename,
    },
    archive_publish::{
        ArchiveBatchDestinationIdentity, ArchiveBatchPublication, ArchiveBatchRecovery,
        recover_archive_publication_batch_with_expected_context,
    },
};
pub(super) fn lock_descriptor(file: &File) -> Result<()> {
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another publisher/recovery owns this exact intent inode: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub(super) fn create_intent(directory: &Path, value: &Value) -> Result<File> {
    let parent = private_root_directory(directory)?;
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let name = format!(".intent-{clock}-{}.tmp", std::process::id());
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(&name))?;
    ensure!(
        file.metadata()?.uid() == 0 && file.metadata()?.mode() & 0o777 == 0o600,
        "unsafe new intent inode"
    );
    lock_descriptor(&file)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= 8 << 20,
        "publication intent exceeds its private metadata envelope"
    );
    file.write_all(&bytes)?;
    file.sync_all()?;
    let from = std::ffi::CString::new(name)?;
    let to = std::ffi::CString::new("intent.json")?;
    ensure!(
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                from.as_ptr(),
                parent.as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "publication intent already exists or no-clobber publication failed; preserve it and use explicit recovery: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    Ok(file)
}
fn lock_intent(directory: &Path) -> Result<File> {
    let parent = private_root_directory(directory)?;
    let path = directory.join("intent.json");
    canonical(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && m.len() > 0
            && m.len() <= 8 << 20,
        "recovery requires a complete root-owned intent inode"
    );
    lock_descriptor(&file)?;
    ensure!(
        identity(&file.metadata()?) == identity(&fs::symlink_metadata(&path)?),
        "intent path changed during locking"
    );
    file.sync_all()?;
    parent.sync_all()?;
    Ok(file)
}
fn existing_binding(path: &Path) -> Result<Evidence> {
    canonical(path)?;
    let mut file = open_regular_nofollow(path)?;
    let before = identity(&file.metadata()?);
    ensure!(
        before.uid == 0
            && before.links == 1
            && before.mode & 0o022 == 0
            && before.len > 0
            && before.len <= 8 << 20,
        "recovery context/receipt is not bounded root evidence"
    );
    let mut bytes = Vec::new();
    (&mut file).take((8 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len
            && identity(&file.metadata()?) == before
            && identity(&fs::symlink_metadata(path)?) == before,
        "recovery context/receipt changed"
    );
    Ok(Evidence {
        path: path.into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}
fn context_scope(v: &Value, p: &Plan, b: &Evidence, self_sha: &str, a: &Accepted) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-exact-epoch223-v3-publication-context-v1"
            && v["epoch"] == 223
            && v["plan"] == serde_json::to_value(b)?
            && v["publisher_sha256"] == self_sha
            && v["verification"] == serde_json::to_value(&p.verification)?
            && v["verifier_launch"] == serde_json::to_value(&p.verifier_launch)?
            && v["canonical_boundary_metadata"]
                == serde_json::to_value(&a.inputs.boundary_metadata)?
            && v["archive_sha256"] == p.archive_sha256
            && v["archive_bytes"] == p.archive_bytes
            && v["expected_provenance_sha256"] == a.prepared.provenance_sha256
            && v["private_runner_sha256"] == p.verifier.sha256
            && v["scanner_terminal"] == a.terminal
            && v["scanner_idle"]["schema"] == "jetstreamer-epoch223-source-idle-v1"
            && v["scanner_idle"]["unit"] == qualified::VERIFY_UNIT
            && v["scanner_idle"]["source_archive"].as_str() == a.archive.to_str()
            && v["scanner_idle"]["current_source_idle"] == true
            && v["scanner_idle"]["historical_invocation_id"] == a.terminal["invocation_id"]
            && v["scanner_idle"]["historical_success_proven_by_this_check"] == false
            && v["scanner_idle"]["publication_authorized"] == false,
        "recovery intent is not this exact publisher, plan, verifier and V3 lineage"
    );
    for key in [
        "runtime_registry_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "recovery context acquired authority: {key}"
        );
    }
    Ok(())
}
fn same_copy(m: &fs::Metadata, id: &Identity) -> bool {
    m.is_file() && m.dev() == id.dev && m.ino() == id.ino && m.len() == id.len && m.nlink() == 1
}
fn destination() -> Result<(PathBuf, fs::Metadata)> {
    let path = PathBuf::from("/home/ubuntu/horizon");
    canonical(&path)?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_dir() && m.uid() == UID && m.gid() == GID && m.mode() & 0o7777 == 0o3770,
        "recovery public directory ownership/mode changed"
    );
    Ok((path, m))
}
fn clean_staging_auxiliary(stage: &Path) -> Result<()> {
    for name in ["epoch-223.jet.sha256", "epoch-223.jet.segment.json"] {
        absent(&stage.join(name))?;
    }
    Ok(())
}
fn prepare_own_handoff(
    p: &Plan,
    a: &Accepted,
    destination: &Path,
    dm: &fs::Metadata,
) -> Result<()> {
    // Complete only the private handoff that was authorized by our durable
    // context. A pending batch is authenticated separately before any public
    // recovery; its staging namespace is left alone here.
    if archive_batch_publication_in_progress(destination)? {
        return Ok(());
    }
    let public = destination.join("epoch-223.jet");
    if fs::symlink_metadata(&public).is_ok() {
        return Ok(());
    }
    match fs::symlink_metadata(&a.archive) {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    for suffix in [
        "epoch-223.jet",
        "epoch-223.jet.sha256",
        "epoch-223.jet.segment.json",
    ] {
        absent(&destination.join(suffix))?;
    }
    let parent = p
        .publication_stage
        .parent()
        .context("recovery handoff parent")?;
    canonical(parent)?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && m.mode() & 0o001 != 0
            && m.dev() == dm.dev(),
        "recovery handoff parent changed"
    );
    let file = open_regular_nofollow(&a.archive)?;
    let before = identity(&file.metadata()?);
    ensure!(
        same_copy(&file.metadata()?, &a.identity)
            && matches!(before.uid, 0 | UID)
            && ((before.uid == 0 && before.mode & 0o777 == 0o400)
                || (before.uid == UID
                    && before.gid == GID
                    && matches!(before.mode & 0o777, 0o400 | 0o440))),
        "recovery private copy identity/ownership changed"
    );
    validate_archive(&file, &a.prepared.provenance_sha256)?;
    let measured = measure_open_archive(&file)?;
    ensure!(
        sha256_hex_string(&measured.sha256) == p.archive_sha256
            && identity(&file.metadata()?) == before
            && identity(&fs::symlink_metadata(&a.archive)?) == before,
        "recovery private handoff bytes changed"
    );
    match fs::symlink_metadata(&p.publication_stage) {
        Ok(m) => ensure!(
            m.is_dir()
                && matches!(m.uid(), 0 | UID)
                && m.mode() & 0o777 == 0o700
                && p.publication_stage.canonicalize()? == p.publication_stage,
            "recovery stage owner/type changed"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
            .mode(0o700)
            .create(&p.publication_stage)?,
        Err(e) => return Err(e.into()),
    }
    let stage = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&p.publication_stage)?;
    let staged = p.publication_stage.join("epoch-223.jet");
    absent(&staged)?;
    clean_staging_auxiliary(&p.publication_stage)?;
    absent(&a.archive.with_extension("jet.sha256"))?;
    ensure!(
        unsafe { libc::fchown(stage.as_raw_fd(), UID, GID) } == 0
            && unsafe { libc::fchown(file.as_raw_fd(), UID, GID) } == 0,
        "recovery handoff ownership transition failed"
    );
    prepare_archive_permissions(&file, destination)?;
    file.sync_all()?;
    let from = std::ffi::CString::new(a.archive.as_os_str().as_encoded_bytes())?;
    let to = std::ffi::CString::new(staged.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "recovery private no-clobber handoff rename failed"
    );
    stage.sync_all()?;
    File::open(a.archive.parent().unwrap())?.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn candidate(p: &Plan, a: &Accepted, destination: &Path) -> Result<(File, PathBuf, Identity)> {
    let mut found = Vec::new();
    for path in [
        p.publication_stage.join("epoch-223.jet"),
        destination.join("epoch-223.jet"),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(m) if same_copy(&m, &a.identity) => found.push(path),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    ensure!(
        found.len() == 1,
        "recovery needs exactly one retained verified-copy inode in stage/public namespace"
    );
    let path = found.pop().unwrap();
    let f = open_regular_nofollow(&path)?;
    let id = identity(&f.metadata()?);
    ensure!(
        id.uid == UID && id.gid == GID && id.links == 1 && id.mode & 0o777 == 0o440,
        "recovery verified copy permissions differ"
    );
    Ok((f, path, id))
}
fn receipt_value(p: &Plan, context: &Value, publication: &ArchiveBatchPublication) -> Value {
    let item = &publication.publications[0];
    json!({"schema":"jetstreamer-exact-epoch223-v3-publication-receipt-v1","epoch":223,"context":context,
        "transaction_id":sha256_hex_string(&publication.transaction_id),"archive_path":item.archive_path,"checksum_path":item.checksum_path,
        "archive_sha256":p.archive_sha256,"archive_bytes":p.archive_bytes,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,
        "private_runner_sha256":p.verifier.sha256,"committed":true,"original_assembly_preserved":true,
        "runtime_registry_promoted":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn prior_receipt(v: &Value, p: &Plan, context: &Value, destination: &Path) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-exact-epoch223-v3-publication-receipt-v1"
            && v["epoch"] == 223
            && v["context"] == *context
            && v["transaction_id"]
                .as_str()
                .is_some_and(|s| evidence::is_sha(s) && s.bytes().any(|b| b != b'0'))
            && v["archive_path"].as_str() == destination.join("epoch-223.jet").to_str()
            && v["checksum_path"].as_str() == destination.join("epoch-223.jet.sha256").to_str()
            && v["archive_sha256"] == p.archive_sha256
            && v["archive_bytes"] == p.archive_bytes
            && v["full_verifier_sha256"] == FULL
            && v["plugin_pipeline_sha256"] == PLUGIN
            && v["private_runner_sha256"] == p.verifier.sha256
            && v["committed"] == true
            && v["original_assembly_preserved"] == true,
        "prior publication receipt does not bind this exact ready pair"
    );
    for key in [
        "runtime_registry_promoted",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "prior receipt acquired unrelated authority: {key}"
        );
    }
    Ok(())
}
fn decode_prior_receipt(
    bytes: &[u8],
    p: &Plan,
    context: &Value,
    destination: &Path,
) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes)
        .context("nonempty publication receipt is incomplete; preserve it for operator handoff")?;
    prior_receipt(&value, p, context, destination)?;
    let mut expected = serde_json::to_vec_pretty(&value)?;
    expected.push(b'\n');
    ensure!(
        bytes == expected,
        "nonempty publication receipt differs from the complete canonical bytes; preserve it for operator handoff"
    );
    Ok(value)
}
fn ready_pair(
    p: &Plan,
    a: &Accepted,
    destination: &Path,
    f: &File,
    measured_id: &Identity,
) -> Result<()> {
    let path = destination.join("epoch-223.jet");
    let id = identity(&fs::symlink_metadata(&path)?);
    // The scoped transaction may legitimately rename/chown the same inode.
    // No file contents, length or mtime may change after its complete hashing.
    ensure!(
        id.dev == measured_id.dev
            && id.ino == measured_id.ino
            && id.len == p.archive_bytes
            && id.mtime == measured_id.mtime
            && id.mtime_ns == measured_id.mtime_ns
            && id.uid == UID
            && id.gid == GID
            && id.links == 1
            && id.mode & 0o777 == 0o440
            && identity(&f.metadata()?) == id,
        "recovered public archive is not the measured verified copy"
    );
    validate_archive(f, &a.prepared.provenance_sha256)?;
    absent(&destination.join("epoch-223.jet.segment.json"))?;
    let checksum = path.with_extension("jet.sha256");
    let mut side = open_regular_nofollow(&checksum)?;
    let before = identity(&side.metadata()?);
    ensure!(
        before.uid == UID
            && before.gid == GID
            && before.links == 1
            && before.mode & 0o777 == 0o640
            && before.len <= 256,
        "recovered checksum type/owner differs"
    );
    let mut bytes = Vec::new();
    (&mut side).take(257).read_to_end(&mut bytes)?;
    let expected = archive_checksum_line(
        &digest(&p.archive_sha256)?,
        std::ffi::OsStr::new("epoch-223.jet"),
    )?;
    ensure!(
        bytes == expected.as_bytes()
            && identity(&side.metadata()?) == before
            && identity(&fs::symlink_metadata(&checksum)?) == before,
        "recovered canonical checksum differs"
    );
    Ok(())
}
pub(super) fn run(binding: Evidence, self_sha: &str) -> Result<()> {
    validate_self(self_sha)?;
    let p: Plan = serde_json::from_slice(&root_evidence(&binding, 4 << 20)?)?;
    validate_plan(&p)?;
    let _intent_owner = lock_intent(&p.receipt_directory)?;
    let verification = bound_json(&p.verification)?;
    let accepted = accept(&verification, &p)?;
    private_root_directory(accepted.archive.parent().unwrap())?;
    let context_binding = existing_binding(&p.receipt_directory.join("intent.json"))?;
    let context = bound_json(&context_binding)?;
    context_scope(&context, &p, &binding, self_sha, &accepted)?;
    // Match fresh publication: reject split writable bind mounts and confine
    // writes before creating any missing receipt or gate sink.
    let (destination, dm) = destination()?;
    write_scope::same_mount(&[
        accepted.archive.parent().unwrap(),
        p.publication_stage.parent().unwrap(),
        &destination,
    ])?;
    write_scope::confine(&[
        accepted.archive.parent().unwrap(),
        p.publication_stage.parent().unwrap(),
        &p.receipt_directory,
        &p.full_receipt_directory,
        &p.plugin_receipt_directory,
        &destination,
    ])?;
    let mut receipt = Sink::resume_or_create(&p.receipt_directory, "publication.json")?;
    let mut full_gate = Sink::resume_or_create(&p.full_receipt_directory, "epoch-223.full.ok")?;
    let mut plugin_gate =
        Sink::resume_or_create(&p.plugin_receipt_directory, "epoch-223.plugin.ok")?;
    full_gate.validate_existing(
        format!("{} {FULL} {}\n", p.archive_sha256, p.verifier.sha256).as_bytes(),
    )?;
    plugin_gate.validate_existing(
        format!("{} {PLUGIN} {}\n", p.archive_sha256, p.verifier.sha256).as_bytes(),
    )?;
    let original = open_regular_nofollow(Path::new(qualified::SOURCE))?;
    let original_id: Identity = serde_json::from_value(verification["source_identity"].clone())?;
    ensure!(
        identity(&original.metadata()?) == original_id
            && identity(&fs::symlink_metadata(qualified::SOURCE)?) == original_id,
        "retained original assembly changed before recovery"
    );
    // Reject every nonempty truncated/conflicting receipt before ownership,
    // rename or transaction recovery. In particular a missing final newline
    // is not permission to "complete" otherwise parseable JSON.
    let prior_metadata = match fs::symlink_metadata(p.receipt_directory.join("publication.json")) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let prior = if prior_metadata.is_some_and(|m| m.len() > 0) {
        let b = existing_binding(&p.receipt_directory.join("publication.json"))?;
        let bytes = root_evidence(&b, 4 << 20)?;
        let value = decode_prior_receipt(&bytes, &p, &context, &destination)?;
        receipt.validate_existing(&bytes)?;
        Some(value)
    } else {
        None
    };
    prepare_own_handoff(&p, &accepted, &destination, &dm)?;
    let (file, _measured_path, measured_id) = candidate(&p, &accepted, &destination)?;
    validate_archive(&file, &accepted.prepared.provenance_sha256)?;
    let measured = measure_open_archive(&file)?;
    ensure!(
        sha256_hex_string(&measured.sha256) == p.archive_sha256
            && measured_id.len == p.archive_bytes
            && identity(&file.metadata()?) == measured_id,
        "recovery complete-copy digest/identity changed"
    );
    let after = qualified::prepare(&accepted.inputs)?;
    ensure!(
        after.provenance == accepted.prepared.provenance
            && after.assembly == accepted.prepared.assembly
            && identity(&original.metadata()?) == original_id
            && identity(&fs::symlink_metadata(qualified::SOURCE)?) == original_id,
        "recovery protected lineage or original changed while hashing"
    );
    root_evidence(&p.verification, 4 << 20)?;
    root_evidence(&context_binding, 4 << 20)?;
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let mut recovery = Sink::create(
        &p.receipt_directory,
        &format!("recovery-{clock}-{}.json", std::process::id()),
    )?;
    drop_to_archive_owner()?;
    let recovered = recover_archive_publication_batch_with_expected_context(
        &destination,
        ArchiveBatchDestinationIdentity {
            device: dm.dev(),
            inode: dm.ino(),
        },
        digest(&binding.sha256)?,
        &[223],
        &serde_json::to_vec(&context)?,
    )?;
    let mut recovery_recorded = false;
    let publication = match recovered {
        ArchiveBatchRecovery::Committed(value) => Some(value),
        ArchiveBatchRecovery::None if prior.is_some() => None,
        ArchiveBatchRecovery::None | ArchiveBatchRecovery::RolledBack(_) => {
            ensure!(
                prior.is_none(),
                "completed publication cannot restart a rolled-back transaction"
            );
            if let ArchiveBatchRecovery::RolledBack(ref value) = recovered {
                ensure!(
                    value.expected_epochs == [223]
                        && value.manifest_fingerprint == digest(&binding.sha256)?,
                    "foreign rollback result"
                );
                recovery.json(&json!({"schema":"jetstreamer-private-epoch223-publication-rollback-recovery-v1","plan":binding,
                    "context":context_binding,"transaction_id":sha256_hex_string(&value.transaction_id),"rolled_back":true,
                    "canonical_sidecar_authorized":false,"publication_authorized":false,"r2_mutations":false}))?;
                recovery_recorded = true;
                acknowledge_archive_publication_batch(&destination, value.transaction_id)?;
            }
            let staged = p.publication_stage.join("epoch-223.jet");
            ensure!(
                same_copy(&fs::symlink_metadata(&staged)?, &accepted.identity),
                "recovery no longer owns its verified staged copy"
            );
            // The authenticated rollback may rename this same held inode.
            // Refresh only ctime through the existing controlled-rename API;
            // inode, full length and mtime must still match the complete hash.
            let fresh = rebind_validated_after_rename(&file, measured)?;
            ensure!(
                sha256_hex_string(&fresh.sha256) == p.archive_sha256,
                "restored stage digest changed"
            );
            clean_staging_auxiliary(&p.publication_stage)?;
            preflight_archive_publication(&p.publication_stage, &destination)?;
            Some(
                publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
                    digest(&binding.sha256)?,
                    &[223],
                    &[ArchiveBatchItem {
                        epoch: 223,
                        staged_archive: staged,
                        destination_archive: destination.join("epoch-223.jet"),
                        evidence: fresh,
                    }],
                    &serde_json::to_vec(&context)?,
                    Duration::from_secs(60),
                )?,
            )
        }
        ArchiveBatchRecovery::UnarmedMarkerCleared => {
            anyhow::bail!("scoped recovery unexpectedly cleared an unauthenticated marker")
        }
    };
    ready_pair(&p, &accepted, &destination, &file, &measured_id)?;
    ensure!(
        identity(&original.metadata()?) == original_id,
        "original assembly changed during scoped recovery"
    );
    let value = if let Some(publication) = &publication {
        ensure!(
            publication.expected_epochs == [223]
                && publication.manifest_fingerprint == digest(&binding.sha256)?
                && publication.publications.len() == 1
                && publication.publication_context.as_deref()
                    == Some(serde_json::to_vec(&context)?.as_slice())
                && publication.publications[0].archive_path == destination.join("epoch-223.jet")
                && publication.publications[0].checksum_path
                    == destination.join("epoch-223.jet.sha256")
                && publication.publications[0].evidence.sha256 == digest(&p.archive_sha256)?,
            "scoped recovery result differs"
        );
        receipt_value(&p, &context, publication)
    } else {
        prior.context("already acknowledged recovery lacks its durable publication receipt")?
    };
    receipt.json(&value)?;
    if !recovery_recorded {
        recovery.json(&json!({"schema":"jetstreamer-private-epoch223-publication-recovery-v1","plan":binding,
        "context":context_binding,"publication":value,"current_verifier_idle":accepted.idle,"archive_rehashed":true,
        "original_assembly_preserved":true,"runtime_registry_promoted":false,"r2_mutations":false}))?;
    }
    full_gate.write(format!("{} {FULL} {}\n", p.archive_sha256, p.verifier.sha256).as_bytes())?;
    plugin_gate
        .write(format!("{} {PLUGIN} {}\n", p.archive_sha256, p.verifier.sha256).as_bytes())?;
    if let Some(publication) = publication {
        acknowledge_archive_publication_batch(&destination, publication.transaction_id)?;
    }
    println!(
        "epoch 223 exact V3 publication recovery committed locally; no R2 mutation or registry promotion"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Evidence, Accepted, Value) {
        let bound = json!({"path":"/private/input.json","sha256":"a".repeat(64)});
        let plan: Plan=serde_json::from_value(json!({"schema":"jetstreamer-private-epoch223-v3-publication-plan-v1",
            "verification":bound,"verifier":bound,
            "verifier_launch":{"path":"/var/lib/jetstreamer/horizon-223-private-verification-capture-v1/launch.json","sha256":"a".repeat(64)},
            "verifier_terminal_journal":bound,"archive_sha256":"b".repeat(64),"archive_bytes":100,
            "publication_stage":"/var/lib/jetstreamer/horizon-223-publication-work-test/stage",
            "receipt_directory":"/private/import","full_receipt_directory":"/private/full","plugin_receipt_directory":"/private/plugin",
            "artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false})).unwrap();
        let inputs: qualified::Inputs=serde_json::from_value(json!({"handoff_request":bound,"handoff_receipt":bound,
            "assembly_plan":bound,"assembly_launch":bound,"assembly_receipt":bound,"assembly_terminal_journal":bound,
            "boundary_metadata":bound,"boundary_collector":bound})).unwrap();
        let path =
            PathBuf::from("/var/lib/jetstreamer/horizon-223-private-v3-scan-test/epoch-223.jet");
        let a = Accepted {
            archive: path.clone(),
            identity: Identity {
                dev: 1,
                ino: 2,
                len: 100,
                uid: 0,
                gid: 0,
                mode: 0o100400,
                links: 1,
                mtime: 1,
                mtime_ns: 0,
                ctime: 1,
                ctime_ns: 0,
            },
            inputs,
            prepared: qualified::Prepared {
                assembly: Value::Null,
                launch: Value::Null,
                boundary: Value::Null,
                provenance: vec![],
                provenance_sha256: "c".repeat(64),
                expected_updates: 0,
                terminal_history: Value::Null,
            },
            terminal: json!({"actual_success_history_validated":true,"invocation_id":"1".repeat(32)}),
            idle: Value::Null,
        };
        let binding = Evidence {
            path: "/private/plan.json".into(),
            sha256: "d".repeat(64),
        };
        let context = json!({"schema":"jetstreamer-exact-epoch223-v3-publication-context-v1","epoch":223,"plan":binding,
            "publisher_sha256":"e".repeat(64),"verification":plan.verification,"verifier_launch":plan.verifier_launch,
            "canonical_boundary_metadata":a.inputs.boundary_metadata,"archive_sha256":plan.archive_sha256,"archive_bytes":plan.archive_bytes,
            "expected_provenance_sha256":a.prepared.provenance_sha256,"private_runner_sha256":plan.verifier.sha256,"scanner_terminal":a.terminal,
            "scanner_idle":{"schema":"jetstreamer-epoch223-source-idle-v1","unit":qualified::VERIFY_UNIT,"source_archive":path,"current_source_idle":true,"historical_invocation_id":"1".repeat(32),"historical_success_proven_by_this_check":false,"publication_authorized":false},
            "runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (plan, binding, a, context)
    }
    #[test]
    fn a_fresh_retry_never_adopts_or_removes_unrelated_staging_metadata() {
        let t = tempfile::tempdir().unwrap();
        clean_staging_auxiliary(t.path()).unwrap();
        for name in ["epoch-223.jet.sha256", "epoch-223.jet.segment.json"] {
            let path = t.path().join(name);
            fs::write(&path, b"preserve unexpected metadata").unwrap();
            assert!(clean_staging_auxiliary(t.path()).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"preserve unexpected metadata");
            fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn the_same_intent_inode_excludes_a_live_duplicate_recovery() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("intent.json");
        fs::write(&path, b"fixture").unwrap();
        let a = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let b = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock_descriptor(&a).unwrap();
        assert!(lock_descriptor(&b).is_err());
        drop(a);
        lock_descriptor(&b).unwrap();
    }
    #[test]
    fn verified_copy_binding_survives_rename_but_rejects_aliases_and_replacements() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("source.jet");
        fs::write(&path, b"fixture retained verified bytes").unwrap();
        let id = identity(&fs::symlink_metadata(&path).unwrap());
        assert!(same_copy(&fs::symlink_metadata(&path).unwrap(), &id));
        let alias = t.path().join("alias.jet");
        symlink(&path, &alias).unwrap();
        assert!(!same_copy(&fs::symlink_metadata(&alias).unwrap(), &id));
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(!same_copy(&fs::symlink_metadata(&path).unwrap(), &id));
        fs::remove_file(&alias).unwrap();
        let retained = t.path().join("retained.jet");
        fs::rename(&path, &retained).unwrap();
        assert!(same_copy(&fs::symlink_metadata(&retained).unwrap(), &id));
        fs::write(&path, b"fixture retained verified bytes").unwrap();
        assert!(!same_copy(&fs::symlink_metadata(&path).unwrap(), &id));
        fs::write(&retained, b"changed length").unwrap();
        assert!(!same_copy(&fs::symlink_metadata(&retained).unwrap(), &id));
    }
    #[test]
    fn recovery_intent_must_match_the_actual_plan_lineage_and_prior_success() {
        let (p, b, a, c) = fixture();
        context_scope(&c, &p, &b, &"e".repeat(64), &a).unwrap();
        for (key, value) in [
            ("epoch", json!(224)),
            ("publisher_sha256", json!("f".repeat(64))),
            ("archive_sha256", json!("f".repeat(64))),
            ("private_runner_sha256", json!("f".repeat(64))),
            ("expected_provenance_sha256", json!("f".repeat(64))),
            ("scanner_terminal", Value::Null),
            ("runtime_registry_promotion_authorized", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = c.clone();
            bad[key] = value;
            assert!(
                context_scope(&bad, &p, &b, &"e".repeat(64), &a).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn already_acknowledged_retry_needs_the_exact_durable_publication_receipt() {
        let (p, _, _, context) = fixture();
        let destination = Path::new("/public/horizon");
        let v = json!({"schema":"jetstreamer-exact-epoch223-v3-publication-receipt-v1","epoch":223,"context":context,
            "transaction_id":"f".repeat(64),"archive_path":destination.join("epoch-223.jet"),"checksum_path":destination.join("epoch-223.jet.sha256"),
            "archive_sha256":p.archive_sha256,"archive_bytes":p.archive_bytes,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,
            "private_runner_sha256":p.verifier.sha256,"committed":true,"original_assembly_preserved":true,
            "runtime_registry_promoted":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        prior_receipt(&v, &p, &context, destination).unwrap();
        let mut bytes = serde_json::to_vec_pretty(&v).unwrap();
        bytes.push(b'\n');
        decode_prior_receipt(&bytes, &p, &context, destination).unwrap();
        for cut in [1, bytes.len() - 1] {
            let error = decode_prior_receipt(&bytes[..cut], &p, &context, destination).unwrap_err();
            assert!(error.to_string().contains("operator handoff"));
        }
        let compact = serde_json::to_vec(&v).unwrap();
        assert!(decode_prior_receipt(&compact, &p, &context, destination).is_err());
        for (key, value) in [
            ("transaction_id", json!("0".repeat(64))),
            ("committed", json!(false)),
            ("original_assembly_preserved", json!(false)),
            ("archive_path", json!("/other/epoch-223.jet")),
            ("context", Value::Null),
            ("runtime_registry_promoted", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(
                prior_receipt(&bad, &p, &context, destination).is_err(),
                "{key}"
            );
        }
    }
}
