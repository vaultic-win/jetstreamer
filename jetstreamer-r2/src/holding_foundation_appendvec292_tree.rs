//! Compare every member of the authenticated sparse bundle to the closed tree
//! without materializing another 432 GB working set.

use super::*;
use std::{
    ffi::CString,
    process::{Command, Stdio},
};

pub(crate) const TAR: &str = "/usr/bin/tar";
const TAR_SHA: &str = "6ab7a3e80cfd4ab35650bf11f48b662f616cd622c1f67d367d0341bc2f9c2245";
pub(crate) const ZSTD: &str = "/usr/bin/zstd";
const ZSTD_SHA: &str = "35bfa0d33c03bc1d74ade24ceae006098fa2d5e7c9addc7be45640832f9384d6";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    restoration: Bound,
}

pub(crate) fn require_read_only(path: &Path) -> Result<()> {
    ensure!(path.canonicalize()? == path, "aliased tree or bundle");
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    ensure!(
        value.f_flag & libc::ST_RDONLY != 0,
        "292 comparison inputs must be read-only mounts"
    );
    Ok(())
}

pub(crate) fn require_no_xattrs(path: &Path) -> Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())?;
    let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(size == 0, "unexpected sparse-tree extended attributes");
    Ok(())
}

fn mtime_ns(m: &fs::Metadata) -> Result<i64> {
    m.mtime()
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(m.mtime_nsec()))
        .context("292 metadata timestamp overflow")
}

fn verify_directory(path: &Path, expected: &Value) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && *expected
                == json!({"uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,
        "mtime_ns":mtime_ns(&m)?,"device":m.dev(),"inode":m.ino()}),
        "292 source directory metadata differs at {}",
        path.display()
    );
    require_no_xattrs(path)?;
    Ok(m)
}

pub(crate) fn appendvec_name(name: &str) -> bool {
    name.split_once('.').is_some_and(|(slot, id)| {
        !slot.is_empty()
            && !id.is_empty()
            && slot.bytes().chain(id.bytes()).all(|b| b.is_ascii_digit())
    })
}

fn compare_census(root: &Path, expected: &Value) -> Result<()> {
    let directories = &expected["directory_metadata"];
    let root_meta = verify_directory(root, &directories["."])?;
    let root_names = fs::read_dir(root)?
        .map(|item| item.map(|entry| entry.file_name()))
        .collect::<std::io::Result<BTreeSet<_>>>()?;
    ensure!(
        root_names
            == ["0", "1", "2", "3"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect(),
        "unexpected 292 source directory entries"
    );
    let mut digest = Sha256::new();
    let (mut files, mut logical, mut allocated) = (0u64, 0u64, 0u64);
    for shard in ["0", "1", "2", "3"] {
        let directory = root.join(shard);
        let metadata = verify_directory(&directory, &directories[shard])?;
        ensure!(
            metadata.dev() == root_meta.dev(),
            "292 source shard crosses filesystem"
        );
        let mut paths = fs::read_dir(&directory)?
            .map(|item| item.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort_unstable();
        for path in paths {
            let leaf = path
                .file_name()
                .and_then(|value| value.to_str())
                .context("invalid 292 member name")?;
            let m = fs::symlink_metadata(&path)?;
            ensure!(
                appendvec_name(leaf)
                    && m.is_file()
                    && m.dev() == root_meta.dev()
                    && m.uid() == 1000
                    && m.nlink() == 1,
                "invalid 292 member {}",
                path.display()
            );
            require_no_xattrs(&path)?;
            // The original census uses compact JSON and one LF per member.
            digest.update(serde_json::to_vec(&json!([
                format!("{shard}/{leaf}"),
                m.uid(),
                m.gid(),
                m.mode() & 0o7777,
                m.len(),
                mtime_ns(&m)?
            ]))?);
            digest.update(b"\n");
            files += 1;
            logical = logical
                .checked_add(m.len())
                .context("292 logical byte overflow")?;
            let bytes = m
                .blocks()
                .checked_mul(512)
                .context("292 allocation overflow")?;
            allocated = allocated
                .checked_add(bytes)
                .context("292 allocation sum overflow")?;
        }
        let after = verify_directory(&directory, &directories[shard])?;
        ensure!(
            (metadata.ctime(), metadata.ctime_nsec()) == (after.ctime(), after.ctime_nsec()),
            "292 source directory changed during census"
        );
    }
    let root_after = verify_directory(root, &directories["."])?;
    ensure!(
        (root_meta.ctime(), root_meta.ctime_nsec())
            == (root_after.ctime(), root_after.ctime_nsec())
            && (files, logical, allocated) == (FILES, LOGICAL_BYTES, PHYSICAL_BYTES)
            && expected["ordered_restore_metadata_sha256"] == hex_lower(&digest.finalize()),
        "292 complete source metadata census differs"
    );
    Ok(())
}

pub(crate) fn verify_tools() -> Result<()> {
    for (path, sha) in [(TAR, TAR_SHA), (ZSTD, ZSTD_SHA)] {
        ensure!(
            hex_lower(&Sha256::digest(read_stable_bounded(
                Path::new(path),
                8 << 20,
                "292 sparse restore tool"
            )?)) == sha,
            "292 sparse restore tool changed at {path}"
        );
    }
    Ok(())
}

pub(crate) fn compare_payload(bundle: &Path, source: &Path, expected: FileIdentity) -> Result<()> {
    verify_tools()?;
    let bundle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(bundle)?;
    ensure!(
        identity(&bundle.metadata()?) == expected,
        "292 bundle changed before decoding"
    );
    let mut decoder = Command::new(ZSTD)
        .env_clear()
        .args(["-qdc", "-"])
        .stdin(Stdio::from(bundle))
        .stdout(Stdio::piped())
        .spawn()?;
    let stream = decoder.stdout.take().context("missing Zstandard pipe")?;
    let comparison = Command::new(TAR)
        .env_clear()
        .env("LC_ALL", "C")
        .args([
            "--compare",
            "--sparse",
            "--numeric-owner",
            "--file=-",
            "--directory",
        ])
        .arg(source)
        .stdin(Stdio::from(stream))
        .status();
    if comparison.as_ref().is_err() {
        let _ = decoder.kill();
    }
    let decoded = decoder.wait()?;
    ensure!(
        comparison?.success() && decoded.success(),
        "292 full sparse payload comparison failed"
    );
    Ok(())
}

pub(super) fn run(value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    ensure!(
        plan.schema == "foundation-epoch292-appendvec-check-tree-v1",
        "foreign 292 tree comparison plan"
    );
    let custody = saved(&plan.custody)?;
    let validated = validate_custody(&custody)?;
    let body = &validated.body;
    let restored = saved(&plan.restoration)?;
    let bundle = Path::new(STATE)
        .join("restores")
        .join(format!("{}.blob", body.sha256));
    ensure!(
        restored["schema"] == "foundation-epoch292-appendvec-byte-restoration-v1"
            && restored["destination"] == bundle.to_string_lossy().as_ref()
            && restored["custody"] == serde_json::to_value(&plan.custody)?
            && restored["object_key"] == validated.object
            && restored["object_etag"] == validated.etag
            && restored["sha256"] == body.sha256
            && restored["length"] == body.length
            && restored["compressed_bundle_restored"] == true
            && restored["remote_sha256_readback"] == true
            && restored["local_retirement_authorized"] == false,
        "292 comparison requires exact authenticated local restoration"
    );
    let (proof, _) = compare(&bundle, body, &custody["manifest"]["restore_metadata"])?;
    let output = receipt(
        &format!("appendvec292-tree-comparison-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch292-appendvec-tree-comparison-v1","spec":spec,"custody":plan.custody,
            "restoration":plan.restoration,"source":proof["source"],"bundle_sha256":body.sha256,"members":FILES,
            "logical_bytes":LOGICAL_BYTES,"allocated_bytes":PHYSICAL_BYTES,"metadata":proof["metadata"],
            "tar_sha256":TAR_SHA,"zstd_sha256":ZSTD_SHA,"full_sparse_payload_matches":true,
            "source_census_matches_before_and_after":true,"source_retirement_authorized":false,
            "publication_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

pub(super) fn compare(bundle: &Path, body: &Body, expected: &Value) -> Result<(Value, LocalProof)> {
    let source = Path::new(expected["source"].as_str().context("292 source tree")?);
    require_read_only(source)?;
    require_read_only(bundle)?;
    let identity = regular_identity(bundle)?;
    ensure!(
        identity.length == body.length,
        "292 restored bundle length differs"
    );
    let proof = hash_and_etag(bundle, identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == body.sha256,
        "292 restored bundle no longer matches authenticated custody"
    );
    compare_census(source, expected)?;
    compare_payload(bundle, source, identity)?;
    compare_census(source, expected)?;
    ensure!(
        regular_identity(bundle)? == identity,
        "292 restored bundle changed during comparison"
    );
    Ok((
        json!({
            "source":source,"metadata":expected,"members":FILES,"logical_bytes":LOGICAL_BYTES,
            "allocated_bytes":PHYSICAL_BYTES,"tar_sha256":TAR_SHA,"zstd_sha256":ZSTD_SHA,
            "full_sparse_payload_matches":true,"source_census_matches_before_and_after":true
        }),
        proof,
    ))
}
