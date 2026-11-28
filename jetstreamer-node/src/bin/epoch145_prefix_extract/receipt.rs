//! Stable metadata reads and guarded copies; original input handles are read-only.
use super::contract::{Bound, Identity};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(super) fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
pub(super) fn open(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical extraction path"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        f.metadata()?.is_file()
            && identity(&f.metadata()?) == identity(&fs::symlink_metadata(path)?),
        "input is not a stable regular file"
    );
    Ok(f)
}
pub(super) fn unchanged(path: &Path, f: &File, wanted: &Identity) -> Result<()> {
    ensure!(
        identity(&f.metadata()?) == *wanted && identity(&fs::symlink_metadata(path)?) == *wanted,
        "original input identity changed"
    );
    Ok(())
}
fn read_as(path: &Path, maximum: u64, uid: u32, immutable: bool) -> Result<Vec<u8>> {
    let mut f = open(path)?;
    let before = identity(&f.metadata()?);
    ensure!(
        before.uid == uid
            && before.links == 1
            && before.bytes <= maximum
            && before.mode & if immutable { 0o222 } else { 0o022 } == 0,
        "unsafe metadata custody, mode or bound"
    );
    let mut bytes = Vec::new();
    (&mut f).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.bytes,
        "metadata grew or truncated"
    );
    unchanged(path, &f, &before)?;
    Ok(bytes)
}
pub(super) fn bound(b: &Bound) -> Result<Value> {
    ensure!(
        super::contract::hex(&b.sha256, 64),
        "invalid metadata digest"
    );
    let bytes = read_as(&b.path, 16 << 20, 0, false)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "bound metadata digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn private_json(path: &Path) -> Result<Value> {
    ensure!(
        fs::symlink_metadata(path)?.mode() & 0o077 == 0,
        "receipt is not owner-private"
    );
    Ok(serde_json::from_slice(&read_as(path, 1 << 20, 0, false)?)?)
}
pub(super) fn hash_file(path: &Path) -> Result<String> {
    let mut f = open(path)?;
    let before = identity(&f.metadata()?);
    let mut hash = Sha256::new();
    std::io::copy(&mut f, &mut hash)?;
    unchanged(path, &f, &before)?;
    Ok(format!("{:x}", hash.finalize()))
}
pub(super) fn directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        let parent = fs::symlink_metadata(path.parent().context("private directory parent")?)?;
        ensure!(
            parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0,
            "untrusted private parent"
        );
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private directory custody changed"
    );
    Ok(())
}
pub(super) fn persist(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    directory(parent)?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(f.as_file_mut(), value)?;
    f.as_file_mut().write_all(b"\n")?;
    ensure!(
        f.as_file().metadata()?.len() <= 1 << 20,
        "receipt exceeds its bound"
    );
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt already exists or commit failed: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) fn available(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(p.as_ptr(), raw.as_mut_ptr()) } == 0,
        "filesystem availability query failed"
    );
    let raw = unsafe { raw.assume_init() };
    u64::try_from(u128::from(raw.f_bavail) * u128::from(raw.f_frsize))
        .context("filesystem free overflow")
}
fn copy_exact(
    source: &Path,
    original: &mut File,
    wanted: &Identity,
    digest: &str,
    sink: &mut impl Write,
    guard: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut hash = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        guard()?;
        let n = original.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        copied = copied
            .checked_add(n as u64)
            .context("source copy counter overflow")?;
        ensure!(
            copied <= wanted.bytes,
            "original copy grew past exact source size"
        );
        sink.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
    }
    ensure!(
        copied == wanted.bytes && format!("{:x}", hash.finalize()) == digest,
        "original copy length or digest differs"
    );
    unchanged(source, original, wanted)?;
    Ok(())
}

/// Copies and hashes the original without chmod/chown/utimens or writable opens.
/// The separate root-owned inode is frozen only after a complete guarded copy.
pub(super) fn frozen_copy(
    source: &Path,
    wanted: &Identity,
    digest: &str,
    target: &Path,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<Identity> {
    guard()?;
    let mut original = open(source)?;
    unchanged(source, &original, wanted)?;
    if target.try_exists()? {
        let mut existing = open(target)?;
        let id = identity(&existing.metadata()?);
        ensure!(
            id.uid == 0
                && id.mode == 0o400
                && id.links == 1
                && id.bytes == wanted.bytes
                && id.inode != wanted.inode,
            "existing frozen copy is foreign"
        );
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            guard()?;
            let n = existing.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure!(
            format!("{:x}", hash.finalize()) == digest,
            "existing frozen copy digest differs"
        );
        unchanged(target, &existing, &id)?;
        unchanged(source, &original, wanted)?;
        return Ok(id);
    }
    let parent = target.parent().context("frozen copy parent")?;
    directory(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    copy_exact(
        source,
        &mut original,
        wanted,
        digest,
        tmp.as_file_mut(),
        &mut guard,
    )?;
    unchanged(source, &original, wanted)?;
    guard()?;
    tmp.as_file().sync_all()?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    tmp.as_file().sync_all()?;
    let result = publish_copy(tmp, target, wanted)?;
    ensure!(result.uid == 0, "frozen copy must have root custody");
    unchanged(source, &original, wanted)?;
    Ok(result)
}

fn publish_copy(
    tmp: tempfile::NamedTempFile,
    target: &Path,
    wanted: &Identity,
) -> Result<Identity> {
    let parent = target.parent().context("published copy parent")?;
    let temporary = identity(&tmp.as_file().metadata()?);
    ensure!(
        temporary.mode == 0o400
            && temporary.bytes == wanted.bytes
            && (temporary.device != wanted.device || temporary.inode != wanted.inode),
        "copy aliases original inode"
    );
    tmp.persist_noclobber(target)
        .map_err(|e| anyhow::anyhow!("frozen source copy conflicts: {e}"))?;
    File::open(parent)?.sync_all()?;
    // persist_noclobber may use link/unlink, which changes ctime even though
    // the bytes and final link count do not change. Bind the published inode.
    let published = open(target)?;
    let result = identity(&published.metadata()?);
    ensure!(
        result.device == temporary.device
            && result.inode == temporary.inode
            && result.bytes == wanted.bytes
            && result.uid == temporary.uid
            && result.mode == 0o400
            && result.links == 1,
        "published frozen copy identity differs"
    );
    unchanged(target, &published, &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separate_copy_preserves_original_bytes_mode_uid_and_ctime() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("original");
        fs::write(&path, b"whole source including private tail").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut f = open(&path).unwrap();
        let wanted = identity(&f.metadata().unwrap());
        let mut sink = Vec::new();
        copy_exact(
            &path,
            &mut f,
            &wanted,
            &format!(
                "{:x}",
                Sha256::digest(b"whole source including private tail")
            ),
            &mut sink,
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(sink, b"whole source including private tail");
        assert_eq!(identity(&fs::symlink_metadata(&path).unwrap()), wanted);
    }
    #[test]
    fn failed_guard_prevents_copy_write_and_digest_mismatch_cannot_qualify_copy() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("original");
        fs::write(&path, b"bytes").unwrap();
        let mut f = open(&path).unwrap();
        let wanted = identity(&f.metadata().unwrap());
        let mut sink = Vec::new();
        assert!(
            copy_exact(
                &path,
                &mut f,
                &wanted,
                &"0".repeat(64),
                &mut sink,
                &mut || anyhow::bail!("guard failed")
            )
            .is_err()
        );
        assert!(sink.is_empty());
        let mut f = open(&path).unwrap();
        assert!(
            copy_exact(
                &path,
                &mut f,
                &wanted,
                &"0".repeat(64),
                &mut sink,
                &mut || Ok(())
            )
            .is_err()
        );
        assert_eq!(identity(&fs::symlink_metadata(&path).unwrap()), wanted);
    }
    #[test]
    fn bounded_reader_rejects_symlink_hardlink_and_writable_immutable_metadata() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("source");
        fs::write(&p, b"{}").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(read_as(&p, 16, uid, true).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_as(&p, 16, uid, true).unwrap(), b"{}");
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        assert!(read_as(&alias, 16, uid, true).is_err());
        fs::remove_file(alias).unwrap();
        fs::hard_link(&p, d.path().join("hard")).unwrap();
        assert!(read_as(&p, 16, uid, true).is_err());
    }
    #[test]
    fn unchanged_detects_replacement_and_original_metadata_changes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("source");
        fs::write(&p, b"same").unwrap();
        let f = open(&p).unwrap();
        let id = identity(&f.metadata().unwrap());
        fs::rename(&p, d.path().join("old")).unwrap();
        fs::write(&p, b"same").unwrap();
        assert!(unchanged(&p, &f, &id).is_err());
    }
    #[test]
    fn published_copy_receipt_binds_final_ctime_and_exact_inode() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("original");
        fs::write(&source, b"source").unwrap();
        let original = identity(&fs::symlink_metadata(&source).unwrap());
        let mut tmp = tempfile::NamedTempFile::new_in(d.path()).unwrap();
        tmp.write_all(b"source").unwrap();
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))
            .unwrap();
        tmp.as_file().sync_all().unwrap();
        let target = d.path().join("frozen");
        let actual = publish_copy(tmp, &target, &original).unwrap();
        assert_eq!(actual, identity(&fs::symlink_metadata(&target).unwrap()));
        assert_eq!(actual.links, 1);
        assert_eq!(actual.mode, 0o400);
        assert_eq!(fs::read(&target).unwrap(), b"source");
        assert_eq!(identity(&fs::symlink_metadata(&source).unwrap()), original);
    }
}
