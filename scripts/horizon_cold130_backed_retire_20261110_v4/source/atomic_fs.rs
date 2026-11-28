//! Linux-only descriptor-relative, no-clobber receipt and capture primitives.
//! Every caller must hold the private operation lock throughout use.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
const MAX_RECEIPT: u64 = 2 << 20;
fn leaf(name: &str) -> Result<CString> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "invalid leaf"
    );
    Ok(CString::new(name)?)
}
pub(crate) fn open_at(parent: &File, name: &str, flags: i32) -> Result<File> {
    let name = leaf(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("descriptor-relative open");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn dir_identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode()})
}
/// Resolve every component beneath a pinned root descriptor without symlinks.
/// Keep all descriptors open so the caller can recheck each path/identity.
pub(crate) struct AnchoredParent {
    pub(crate) directory: File,
    chain: Vec<(std::path::PathBuf, File, Value)>,
}
impl AnchoredParent {
    pub(crate) fn open(path: &Path, expected: &Value) -> Result<Self> {
        ensure!(path.is_absolute(), "absolute parent required");
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let mut chain = vec![(
            std::path::PathBuf::from("/"),
            current.try_clone()?,
            dir_identity(&current.metadata()?),
        )];
        let mut at = std::path::PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let name = name.to_str().context("non-UTF8 ancestor")?;
                    current = open_at(&current, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    at.push(name);
                    let identity = dir_identity(&current.metadata()?);
                    chain.push((at.clone(), current.try_clone()?, identity));
                }
                _ => anyhow::bail!("ambiguous ancestor"),
            }
        }
        let actual: Vec<Value> = chain
            .iter()
            .map(|(p, _, id)| json!({"path":p,"identity":id}))
            .collect();
        ensure!(
            json!(actual) == *expected,
            "source ancestor custody differs"
        );
        Ok(Self {
            directory: current,
            chain,
        })
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        for (path, fd, expected) in &self.chain {
            ensure!(
                dir_identity(&fd.metadata()?) == *expected,
                "ancestor descriptor changed"
            );
            let direct = fs::symlink_metadata(path)?;
            ensure!(
                direct.is_dir() && dir_identity(&direct) == *expected,
                "source ancestor path replaced"
            );
        }
        Ok(())
    }
}
pub(crate) fn exists_at(parent: &File, name: &str) -> Result<bool> {
    match open_at(parent, name, libc::O_PATH) {
        Ok(_) => Ok(true),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn rename_no_replace(
    from: &File,
    source: &str,
    to: &File,
    destination: &str,
) -> Result<()> {
    let source = leaf(source)?;
    let destination = leaf(destination)?;
    let result = unsafe {
        libc::renameat2(
            from.as_raw_fd(),
            source.as_ptr(),
            to.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("no-clobber capture/publication");
    }
    Ok(())
}
pub(crate) fn unlink_at(parent: &File, name: &str) -> Result<()> {
    let name = leaf(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("private captured-inode unlink");
    }
    Ok(())
}
pub(crate) fn private_child(parent: &File, name: &str) -> Result<File> {
    let encoded = leaf(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), encoded.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        ensure!(
            error.kind() == std::io::ErrorKind::AlreadyExists,
            "cannot create private capture directory: {error}"
        );
    } else {
        parent.sync_all()?;
    }
    let dir = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let m = dir.metadata()?;
    ensure!(
        m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o700
            && m.dev() == parent.metadata()?.dev(),
        "private capture custody differs"
    );
    ensure!(
        unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "capture directory already locked"
    );
    Ok(dir)
}
pub(crate) fn read_at(parent: &File, name: &str) -> Result<Vec<u8>> {
    let mut f = open_at(parent, name, libc::O_RDONLY)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == unsafe { libc::geteuid() }
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && m.len() <= MAX_RECEIPT,
        "private receipt custody/bound differs"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(MAX_RECEIPT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len() && stable(&m) == stable(&f.metadata()?),
        "receipt changed during read"
    );
    Ok(bytes)
}
fn stable(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn names(parent: &File) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for e in fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? {
        ensure!(result.len() < 10_000, "private staging entry bound");
        result.push(
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 staging name"))?,
        );
    }
    result.sort();
    Ok(result)
}
/// Preserve interrupted staging files rather than treating them as final receipts.
/// No incomplete final name is ever published and no prior evidence is removed.
pub(crate) fn reconcile_staging(parent: &File) -> Result<Value> {
    let mut preserved = Vec::new();
    for name in names(parent)? {
        if !name.starts_with(".receipt-stage-") {
            continue;
        }
        let bytes = read_at(parent, &name)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let destination = format!("interrupted-{name}-{digest}");
        rename_no_replace(parent, &name, parent, &destination)?;
        parent.sync_all()?;
        preserved.push(json!({"name":destination,"sha256":digest,"length":bytes.len(),"parsed_json":serde_json::from_slice::<Value>(&bytes).is_ok(),"never_accepted_as_final_receipt":true}));
    }
    Ok(json!(preserved))
}
/// Serialize fully before any named filesystem mutation, fsync private staging,
/// then publish through renameat2(RENAME_NOREPLACE) and fsync the directory.
pub(crate) fn publish(parent: &File, name: &str, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "receipt size bound");
    let stage = format!(
        ".receipt-stage-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::SeqCst)
    );
    let encoded = leaf(&stage)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            encoded.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("new receipt staging");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    rename_no_replace(parent, &stage, parent, name)?;
    parent.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn directory(path: &Path) -> File {
        File::open(path).unwrap()
    }
    #[test]
    fn partial_stage_never_blocks_a_later_atomic_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let dir = directory(temp.path());
        fs::write(temp.path().join(".receipt-stage-old"), b"{partial").unwrap();
        fs::set_permissions(
            temp.path().join(".receipt-stage-old"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let recovered = reconcile_staging(&dir).unwrap();
        assert_eq!(recovered.as_array().unwrap().len(), 1);
        assert!(!exists_at(&dir, "intent.json").unwrap());
        publish(&dir, "intent.json", &json!({"complete":true})).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&read_at(&dir, "intent.json").unwrap()).unwrap(),
            json!({"complete":true})
        );
    }
    #[test]
    fn receipt_and_capture_publication_never_clobber() {
        let temp = tempfile::tempdir().unwrap();
        let dir = directory(temp.path());
        publish(&dir, "intent.json", &json!({"first":true})).unwrap();
        assert!(publish(&dir, "intent.json", &json!({"second":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&read_at(&dir, "intent.json").unwrap()).unwrap(),
            json!({"first":true})
        );
        fs::write(temp.path().join("a"), b"original").unwrap();
        fs::write(temp.path().join("b"), b"foreign").unwrap();
        assert!(rename_no_replace(&dir, "a", &dir, "b").is_err());
        assert_eq!(fs::read(temp.path().join("a")).unwrap(), b"original");
        assert_eq!(fs::read(temp.path().join("b")).unwrap(), b"foreign");
    }
    #[test]
    fn symlink_components_and_capture_directory_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = directory(temp.path());
        fs::create_dir(temp.path().join("real")).unwrap();
        symlink("real", temp.path().join("alias")).unwrap();
        assert!(open_at(&dir, "alias", libc::O_RDONLY | libc::O_DIRECTORY).is_err());
        assert!(private_child(&dir, "alias").is_err());
    }
    #[test]
    fn interruption_after_publication_leaves_complete_json() {
        let temp = tempfile::tempdir().unwrap();
        let dir = directory(temp.path());
        publish(&dir, "completion.json", &json!({"done":true,"credit":0})).unwrap();
        assert_eq!(reconcile_staging(&dir).unwrap(), json!([]));
        assert_eq!(
            serde_json::from_slice::<Value>(&read_at(&dir, "completion.json").unwrap()).unwrap()["credit"],
            0
        );
    }
}
