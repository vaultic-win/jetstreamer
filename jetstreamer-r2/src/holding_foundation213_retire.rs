//! Only the original213 prefix and this operation's qualified staging copy.
//! Every unlink is preceded by durable intent and a root-private quarantine.
use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
};

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
pub(in crate::holding) fn id(metadata: &fs::Metadata) -> Value {
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
pub(in crate::holding) fn absence(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn record_file_policy(m: &fs::Metadata, owner: u32, group: u32) -> Result<()> {
    ensure!(
        m.is_file()
            && m.uid() == owner
            && m.gid() == group
            && m.nlink() == 1
            && matches!(m.mode() & 0o7777, 0o400 | 0o440)
            && m.len() <= MAX_RECEIPT_BYTES as u64,
        "unsafe retirement record"
    );
    Ok(())
}
fn record_stamp(m: &fs::Metadata) -> Value {
    json!({"identity":id(m),"ctime":m.ctime(),"ctime_ns":m.ctime_nsec()})
}
fn record_directory_policy(m: &fs::Metadata, owner: u32, group: u32) -> Result<()> {
    ensure!(
        m.is_dir() && m.uid() == owner && m.gid() == group && m.mode() & 0o7777 == 0o700,
        "retirement record ancestry is not private"
    );
    Ok(())
}
fn record_directory_same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
}
fn open_record_child(parent: &File, name: &Path, directory: bool) -> Result<File> {
    let name = child(name)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(
        fd >= 0,
        "cannot open pinned retirement record child: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn record_namespace(
    root: &Path,
    path: &Path,
    root_fd: &File,
    parent_fd: &File,
    file: &File,
    owner: u32,
    group: u32,
) -> Result<()> {
    ensure!(
        root.canonicalize()? == root && path.canonicalize()? == path,
        "aliased retirement record ancestry"
    );
    let parent = path.parent().context("retirement record parent")?;
    let root_now = fs::symlink_metadata(root)?;
    let parent_now = fs::symlink_metadata(parent)?;
    record_directory_policy(&root_now, owner, group)?;
    record_directory_policy(&parent_now, owner, group)?;
    ensure!(
        record_directory_same(&root_now, &root_fd.metadata()?)
            && record_directory_same(&parent_now, &parent_fd.metadata()?),
        "retirement record ancestry changed"
    );
    let entry = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    record_file_policy(&entry, owner, group)?;
    record_file_policy(&opened, owner, group)?;
    ensure!(
        record_stamp(&entry) == record_stamp(&opened),
        "retirement record namespace changed"
    );
    Ok(())
}
fn record_bytes_in(root: &Path, path: &Path, owner: u32, group: u32) -> Result<Vec<u8>> {
    let parent = path.parent().context("retirement record parent")?;
    let parent_name = parent
        .file_name()
        .and_then(|s| s.to_str())
        .context("retirement record directory name")?;
    let suffix = parent_name
        .strip_prefix("retirement-")
        .context("foreign retirement record directory")?;
    ensure!(
        root.is_absolute()
            && parent.parent() == Some(root)
            && suffix.len() == 64
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "foreign retirement record ancestry"
    );
    let root_fd = pinned_directory(root, Some(owner), true)?;
    record_directory_policy(&root_fd.metadata()?, owner, group)?;
    let parent_fd = open_record_child(&root_fd, Path::new(parent_name), true)?;
    record_directory_policy(&parent_fd.metadata()?, owner, group)?;
    let mut file = open_record_child(
        &parent_fd,
        Path::new(path.file_name().context("retirement record basename")?),
        false,
    )?;
    record_namespace(root, path, &root_fd, &parent_fd, &file, owner, group)?;
    let before = file.metadata()?;
    record_file_policy(&before, owner, group)?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len())?);
    std::io::Read::by_ref(&mut file)
        .take(MAX_RECEIPT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    record_file_policy(&after, owner, group)?;
    ensure!(
        bytes.len() as u64 == before.len() && record_stamp(&before) == record_stamp(&after),
        "retirement record changed while read"
    );
    record_namespace(root, path, &root_fd, &parent_fd, &file, owner, group)?;
    Ok(bytes)
}
pub(in crate::holding) fn read_record(path: &Path) -> Result<Value> {
    // Production ownership remains exact root:root; fixture owner parameters
    // are private to the shared implementation and never command inputs.
    Ok(serde_json::from_slice(&record_bytes_in(
        Path::new(STATE),
        path,
        0,
        0,
    )?)?)
}
pub(in crate::holding) fn binding(path: &Path) -> Result<Value> {
    let bytes = record_bytes_in(Path::new(STATE), path, 0, 0)?;
    let _: Value = serde_json::from_slice(&bytes)?;
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
fn restoration_transport(r: &Value) -> Result<()> {
    if r["schema"] == "jetstreamer-foundation-holding-restore-v1" {
        ensure!(
            r["remote_sha256_readback"] == true,
            "legacy restoration lacks full remote readback"
        );
        return Ok(());
    }
    ensure!(
        r["schema"] == "jetstreamer-foundation-holding-resumable-restore-v1"
            && r["artifact"] == "prefix213"
            && r["length"] == review::LENGTH
            && r["sha256"] == review::SOURCE_SHA
            && r["independent_local_sha256_verified"] == true
            && r["conditional_remote_identity_revalidated"] == true
            && r["resumable_transport"]["whole_file_sha256_verified"] == true,
        "new restoration lacks the exact independent whole-file proof"
    );
    let prefix = r["resumable_transport"]["local_prefix_bytes"]
        .as_u64()
        .context("restored local prefix byte count")?;
    let suffix = r["resumable_transport"]["network_suffix_bytes"]
        .as_u64()
        .context("restored network suffix byte count")?;
    ensure!(
        prefix.checked_add(suffix) == Some(review::LENGTH)
            && r["remote_sha256_readback"] == (prefix == 0),
        "restoration byte counts or network/local distinction differ"
    );
    Ok(())
}
fn restoration(r: &Value, c: &Value, p: &Spec) -> Result<()> {
    restoration_transport(r)?;
    ensure!(
        r["host"] == review::HOST
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
pub(in crate::holding) enum ResumeState {
    Move,
    Quarantined,
    Unlinked,
    Complete,
}
pub(in crate::holding) fn resume_state(
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
pub(in crate::holding) fn pinned_directory(
    path: &Path,
    owner: Option<u32>,
    private_mode: bool,
) -> Result<File> {
    ensure!(path.canonicalize()? == path, "aliased retirement directory");
    let before = fs::symlink_metadata(path)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let opened = directory.metadata()?;
    ensure!(
        before.is_dir()
            && opened.is_dir()
            && before.dev() == opened.dev()
            && before.ino() == opened.ino()
            && owner.is_none_or(|uid| opened.uid() == uid)
            && (!private_mode || opened.mode() & 0o7777 == 0o700),
        "retirement directory changed or is unsafe"
    );
    Ok(directory)
}
fn child(path: &Path) -> Result<CString> {
    ensure!(
        path.components().count() == 1 && path.file_name().is_some_and(|n| n == path.as_os_str()),
        "retirement directory operation requires one exact child name"
    );
    Ok(CString::new(path.as_os_str().as_bytes())?)
}
pub(in crate::holding) fn rename_pinned(
    source: &Path,
    directory: &File,
    name: &Path,
) -> Result<()> {
    let parent = pinned_directory(
        source.parent().context("retirement source parent")?,
        None,
        false,
    )?;
    ensure!(
        parent.metadata()?.dev() == directory.metadata()?.dev(),
        "retirement rename crosses filesystems"
    );
    let source_name = child(Path::new(source.file_name().context("source basename")?))?;
    let destination_name = child(name)?;
    ensure!(
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                source_name.as_ptr(),
                directory.as_raw_fd(),
                destination_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "anchored no-clobber retirement rename failed: {}",
        std::io::Error::last_os_error()
    );
    parent.sync_all()?;
    directory.sync_all()?;
    Ok(())
}
pub(in crate::holding) fn unlink_pinned(
    directory: &File,
    name: &Path,
    expected: &Value,
) -> Result<()> {
    let name = child(name)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    ensure!(
        unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0,
        "cannot stat anchored retirement target: {}",
        std::io::Error::last_os_error()
    );
    let m = unsafe { metadata.assume_init() };
    ensure!(
        m.st_mode & libc::S_IFMT == libc::S_IFREG
            && expected["device"].as_u64() == Some(m.st_dev)
            && expected["inode"].as_u64() == Some(m.st_ino)
            && expected["length"].as_u64() == u64::try_from(m.st_size).ok()
            && expected["nlink"].as_u64() == Some(m.st_nlink)
            && expected["uid"].as_u64() == Some(u64::from(m.st_uid))
            && expected["gid"].as_u64() == Some(u64::from(m.st_gid))
            && expected["mode"].as_u64() == Some(u64::from(m.st_mode & 0o7777))
            && expected["mtime"].as_i64() == Some(m.st_mtime)
            && expected["mtime_ns"].as_i64() == Some(m.st_mtime_nsec),
        "anchored retirement target differs from the durably verified identity"
    );
    ensure!(
        unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "anchored retirement unlink failed: {}",
        std::io::Error::last_os_error()
    );
    directory.sync_all()?;
    Ok(())
}
fn retire_one(directory: &Path, p: &Spec, spec: &Bound, original: bool) -> Result<()> {
    let quarantine_directory = pinned_directory(directory, Some(0), true)?;
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
        rename_pinned(
            &source,
            &quarantine_directory,
            Path::new(quarantine.file_name().unwrap()),
        )?;
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
        unlink_pinned(
            &quarantine_directory,
            Path::new(quarantine.file_name().unwrap()),
            expected,
        )?;
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
    fn record_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, u32, u32) {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent = root.path().join(format!("retirement-{}", "a".repeat(64)));
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let path = parent.join("terminal.json");
        (root, parent, path, unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
    #[test]
    fn actual_receipt_writer_and_retirement_reader_are_idempotent_for_0440_and_historical_0400() {
        use std::os::unix::fs::PermissionsExt;
        let (root, _parent, path, owner, group) = record_fixture();
        let value =
            json!({"schema":"fixture-retirement-record-v1","operation":"exact immutable set"});
        durable_receipt(&path, &value).unwrap();
        let first = fs::symlink_metadata(&path).unwrap();
        assert_eq!(first.mode() & 0o7777, 0o440);
        assert_eq!(first.nlink(), 1);
        let bytes = record_bytes_in(root.path(), &path, owner, group).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
        durable_receipt(&path, &value).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), first.ino());
        assert_eq!(
            record_bytes_in(root.path(), &path, owner, group).unwrap(),
            bytes
        );
        assert!(durable_receipt(&path, &json!({"conflicting":"must not replace"})).is_err());
        assert_eq!(
            record_bytes_in(root.path(), &path, owner, group).unwrap(),
            bytes
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            record_bytes_in(root.path(), &path, owner, group).unwrap(),
            bytes
        );
        durable_receipt(&path, &value).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o400);
        assert_eq!(
            record_bytes_in(root.path(), &path, owner, group).unwrap(),
            bytes
        );
    }
    #[test]
    fn record_reader_rejects_other_modes_links_aliases_owners_and_nonprivate_ancestry() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (root, parent, path, owner, group) = record_fixture();
        durable_receipt(&path, &json!({"fixture":true})).unwrap();
        for mode in [0o600, 0o640, 0o444, 0o404, 0o460] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                record_bytes_in(root.path(), &path, owner, group).is_err(),
                "{mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        let linked = parent.join("linked.json");
        fs::hard_link(&path, &linked).unwrap();
        assert!(record_bytes_in(root.path(), &path, owner, group).is_err());
        fs::remove_file(linked).unwrap();
        let saved = parent.join("saved.json");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert!(record_bytes_in(root.path(), &path, owner, group).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(saved, &path).unwrap();
        let m = fs::symlink_metadata(&path).unwrap();
        assert!(record_file_policy(&m, owner.wrapping_add(1), group).is_err());
        assert!(record_file_policy(&m, owner, group.wrapping_add(1)).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(record_bytes_in(root.path(), &path, owner, group).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(record_bytes_in(root.path(), &path, owner, group).is_err());
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            record_bytes_in(
                root.path(),
                &root.path().join("foreign/terminal.json"),
                owner,
                group
            )
            .is_err()
        );
        record_bytes_in(root.path(), &path, owner, group).unwrap();
    }
    #[test]
    fn pinned_record_reader_rejects_same_bytes_under_replaced_file_or_ancestor() {
        use std::os::unix::fs::DirBuilderExt;
        for ancestor in [false, true] {
            let (root, parent, path, owner, group) = record_fixture();
            let value = json!({"same":"bytes do not excuse replacement"});
            durable_receipt(&path, &value).unwrap();
            let root_fd = pinned_directory(root.path(), Some(owner), true).unwrap();
            let parent_fd =
                open_record_child(&root_fd, Path::new(parent.file_name().unwrap()), true).unwrap();
            let file = open_record_child(&parent_fd, Path::new("terminal.json"), false).unwrap();
            record_namespace(
                root.path(),
                &path,
                &root_fd,
                &parent_fd,
                &file,
                owner,
                group,
            )
            .unwrap();
            if ancestor {
                fs::rename(&parent, root.path().join("moved")).unwrap();
                fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
            } else {
                fs::rename(&path, parent.join("old.json")).unwrap();
            }
            durable_receipt(&path, &value).unwrap();
            assert!(
                record_namespace(
                    root.path(),
                    &path,
                    &root_fd,
                    &parent_fd,
                    &file,
                    owner,
                    group
                )
                .is_err()
            );
        }
    }
    #[test]
    fn resumable_restoration_requires_exact_complete_proof_without_relabeling_network_reads() {
        let good = json!({"schema":"jetstreamer-foundation-holding-resumable-restore-v1","artifact":"prefix213",
            "sha256":review::SOURCE_SHA,"length":review::LENGTH,"remote_sha256_readback":false,
            "independent_local_sha256_verified":true,"conditional_remote_identity_revalidated":true,
            "resumable_transport":{"local_prefix_bytes":37,"network_suffix_bytes":review::LENGTH-37,"whole_file_sha256_verified":true}});
        restoration_transport(&good).unwrap();
        for (pointer, value) in [
            ("/artifact", json!("genesis-probe")),
            ("/sha256", json!(PROBE_SHA)),
            ("/remote_sha256_readback", json!(true)),
            ("/independent_local_sha256_verified", json!(false)),
            ("/conditional_remote_identity_revalidated", json!(false)),
            (
                "/resumable_transport/whole_file_sha256_verified",
                json!(false),
            ),
            (
                "/resumable_transport/network_suffix_bytes",
                json!(review::LENGTH - 38),
            ),
            ("/resumable_transport/local_prefix_bytes", json!(u64::MAX)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(restoration_transport(&bad).is_err(), "{pointer}");
        }
        let mut full = good.clone();
        full["resumable_transport"]["local_prefix_bytes"] = json!(0);
        full["resumable_transport"]["network_suffix_bytes"] = json!(review::LENGTH);
        full["remote_sha256_readback"] = json!(true);
        restoration_transport(&full).unwrap();
        let mut legacy = json!({"schema":"jetstreamer-foundation-holding-restore-v1","remote_sha256_readback":true});
        restoration_transport(&legacy).unwrap();
        legacy["remote_sha256_readback"] = json!(false);
        assert!(restoration_transport(&legacy).is_err());
    }
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
    #[test]
    fn renamed_ancestor_cannot_redirect_the_authorized_quarantine_unlink() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("quarantine");
        let moved = root.path().join("moved");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.path().join("source.blob");
        fs::write(&source, b"exact retained fixture").unwrap();
        let expected = id(&fs::symlink_metadata(&source).unwrap());
        let fd = pinned_directory(&path, Some(unsafe { libc::geteuid() }), true).unwrap();
        rename_pinned(&source, &fd, Path::new("source.blob")).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("source.blob"),
            b"unrelated replacement must survive",
        )
        .unwrap();
        unlink_pinned(&fd, Path::new("source.blob"), &expected).unwrap();
        assert!(!moved.join("source.blob").exists());
        assert_eq!(
            fs::read(path.join("source.blob")).unwrap(),
            b"unrelated replacement must survive"
        );
        assert!(child(Path::new("../outside")).is_err());
        assert!(child(Path::new("/absolute")).is_err());
    }
    #[test]
    fn anchored_unlink_requires_the_exact_inode_and_preserves_a_symlink_or_replacement() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("target");
        fs::write(&path, b"first identity").unwrap();
        let expected = id(&fs::symlink_metadata(&path).unwrap());
        let fd = pinned_directory(root.path(), Some(unsafe { libc::geteuid() }), true).unwrap();
        fs::rename(&path, root.path().join("preserved")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(unlink_pinned(&fd, Path::new("target"), &expected).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(root.path().join("preserved"), &path).unwrap();
        assert!(unlink_pinned(&fd, Path::new("target"), &expected).is_err());
        assert_eq!(
            fs::read(root.path().join("preserved")).unwrap(),
            b"first identity"
        );
    }
}
