//! No-follow retained-artifact custody and existing shared-lock identities.
use super::*;
use std::{
    ffi::CString,
    os::{fd::FromRawFd, unix::ffi::OsStrExt},
    path::Component,
};

pub(super) const EPOCH_LOCK: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/locks/epoch-166.lock";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct LockBinding {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Preserved {
    pub identities: BTreeMap<String, Value>,
    pub sha256: BTreeMap<String, String>,
}
pub(super) fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.blocks(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
pub(super) fn directory_identity(m: &fs::Metadata) -> Value {
    json!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode()])
}
pub(super) fn open_directory(path: &Path) -> Result<File> {
    ensure!(path.is_absolute(), "absolute directory required");
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    fd >= 0,
                    "directory component open failed: {}",
                    std::io::Error::last_os_error()
                );
                dir = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical directory component"),
        }
    }
    Ok(dir)
}
pub(super) fn open_regular(path: &Path, uid: u32) -> Result<File> {
    let parent = open_directory(path.parent().context("file parent")?)?;
    let name = CString::new(path.file_name().context("file name")?.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "no-follow file open failed: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && identity(&fs::symlink_metadata(path)?) == identity(&m),
        "unsafe regular file: {}",
        path.display()
    );
    Ok(file)
}
pub(super) fn validate_locks(locks: &[LockBinding]) -> Result<()> {
    let expected = [
        LockBinding {
            path: MUTATION_LOCK.into(),
            device: DEVICE,
            inode: 101135013,
            uid: UID,
            gid: GID,
            mode: 0o600,
        },
        LockBinding {
            path: EPOCH_LOCK.into(),
            device: DEVICE,
            inode: 103678014,
            uid: UID,
            gid: GID,
            mode: 0o600,
        },
    ];
    ensure!(
        locks == expected,
        "exact existing mutation and destination epoch locks required in canonical order"
    );
    Ok(())
}
fn check_lock(binding: &LockBinding, file: &File) -> Result<()> {
    let m = file.metadata()?;
    ensure!(
        m.dev() == binding.device
            && m.ino() == binding.inode
            && m.uid() == binding.uid
            && m.gid() == binding.gid
            && m.mode() & 0o7777 == binding.mode
            && m.is_file()
            && m.nlink() == 1
            && identity(&m) == identity(&fs::symlink_metadata(&binding.path)?),
        "shared lock replaced or changed"
    );
    Ok(())
}
pub(super) fn hold_locks(locks: &[LockBinding]) -> Result<Vec<File>> {
    locks
        .iter()
        .map(|binding| {
            let file = open_regular(&binding.path, binding.uid)?;
            check_lock(binding, &file)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "shared lifecycle lock busy: {}",
                binding.path.display()
            );
            Ok(file)
        })
        .collect()
}
pub(super) fn recheck_locks(bindings: &[LockBinding], files: &[File]) -> Result<()> {
    ensure!(bindings.len() == files.len(), "lock handle count changed");
    for (binding, file) in bindings.iter().zip(files) {
        check_lock(binding, file)?;
    }
    Ok(())
}
pub(super) fn hold_ancestors(path: &Path) -> Result<Vec<(PathBuf, File, Value)>> {
    path.ancestors()
        .map(|ancestor| {
            let file = open_directory(ancestor)?;
            let before = directory_identity(&file.metadata()?);
            Ok((ancestor.to_owned(), file, before))
        })
        .collect()
}
pub(super) fn recheck_ancestors(held: &[(PathBuf, File, Value)]) -> Result<()> {
    for (path, file, before) in held {
        ensure!(
            directory_identity(&file.metadata()?) == *before
                && directory_identity(&open_directory(path)?.metadata()?) == *before,
            "retained ancestor identity changed: {}",
            path.display()
        );
    }
    Ok(())
}
fn hash_retained(path: &Path, uid: u32) -> Result<String> {
    let mut file = open_regular(path, uid)?;
    let before = identity(&file.metadata()?);
    let expected_bytes = file.metadata()?.len();
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 8 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .context("retained file length overflow")?;
        ensure!(total <= expected_bytes, "retained file grew during digest");
        hash.update(&buffer[..n]);
    }
    ensure!(
        total == expected_bytes
            && identity(&file.metadata()?) == before
            && identity(&fs::symlink_metadata(path)?) == before,
        "retained file changed during digest"
    );
    Ok(format!("{:x}", hash.finalize()))
}
fn retained_walk(
    root: &Path,
    path: &Path,
    out: &mut Preserved,
    hashes: bool,
    owner: (u64, u32, u32),
    depth: usize,
) -> Result<()> {
    let (expected_device, uid, gid) = owner;
    ensure!(
        depth <= 128 && out.identities.len() < 100_000,
        "retained artifact census exceeds budget"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == expected_device
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o022 == 0
            && (m.is_dir() || m.is_file())
            && (m.is_dir() || m.nlink() == 1),
        "foreign or aliased retained artifact: {}",
        path.display()
    );
    let relative = path
        .strip_prefix(root)?
        .to_str()
        .context("retained path UTF8")?
        .to_owned();
    let before = identity(&m);
    out.identities.insert(relative.clone(), before.clone());
    if m.is_dir() {
        let dir = open_directory(path)?;
        ensure!(
            identity(&dir.metadata()?) == before,
            "retained directory changed while opening"
        );
        for entry in fs::read_dir(path)? {
            retained_walk(root, &entry?.path(), out, hashes, owner, depth + 1)?;
        }
    } else if hashes {
        out.sha256.insert(relative, hash_retained(path, uid)?);
    }
    ensure!(
        identity(&fs::symlink_metadata(path)?) == before,
        "retained artifact changed during census"
    );
    Ok(())
}
pub(super) fn preserved(hashes: bool, held: Option<&Bound>) -> Result<Preserved> {
    let root = Path::new(RUN);
    let m = open_directory(root)?.metadata()?;
    ensure!(
        m.dev() == DEVICE && m.ino() == RUN_INODE && m.uid() == UID && m.gid() == GID,
        "run identity changed"
    );
    let names: BTreeSet<_> = fs::read_dir(root)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("nonUTF8 run entry"))
        })
        .collect::<Result<_>>()?;
    ensure!(
        names
            == BTreeSet::from([
                "archives".into(),
                "inputs".into(),
                "cohort-state.json".into(),
                "scratch".into()
            ]),
        "unexpected retained run member; review new continuation evidence"
    );
    let state = fs::symlink_metadata(root.join("cohort-state.json"))?;
    ensure!(
        state.ino() == STATE_INODE && state.len() == STATE_BYTES,
        "protected state differs from exact run"
    );
    let archive_names: Vec<_> = fs::read_dir(root.join("archives"))?
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<_>>()?;
    if held.is_some() {
        ensure!(
            archive_names.is_empty(),
            "held partial mode requires empty preserved archives directory"
        );
    } else {
        let archive = fs::symlink_metadata(root.join("archives/epoch-166.jet"))?;
        ensure!(
            archive.ino() == ARCHIVE_INODE && archive.len() == ARCHIVE_BYTES,
            "protected archive differs from exact run"
        );
        ensure!(
            archive_names == [std::ffi::OsString::from("epoch-166.jet")],
            "unreviewed extra archive or continuation artifact"
        );
    }
    let scratch = fs::symlink_metadata(SCRATCH)?;
    ensure!(
        scratch.is_dir()
            && scratch.dev() == DEVICE
            && scratch.ino() == SCRATCH_INODE
            && scratch.uid() == UID
            && scratch.gid() == GID,
        "scratch root changed"
    );
    let mut out = Preserved {
        identities: BTreeMap::new(),
        sha256: BTreeMap::new(),
    };
    out.identities.insert("".into(), identity(&m));
    // Removing children changes scratch clocks and link count. Preserve its
    // identity/mode and ancestry rather than treating those expected changes as replacement.
    out.identities
        .insert("scratch".into(), directory_identity(&scratch));
    for name in ["archives", "inputs", "cohort-state.json"] {
        retained_walk(
            root,
            &root.join(name),
            &mut out,
            hashes,
            (DEVICE, UID, GID),
            0,
        )?;
    }
    if let Some(binding) = held {
        let proof = held_partial::verify(binding, &out.identities)?;
        out.identities.insert("held_partial_custody".into(), proof);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn content_proof_detects_same_size_sibling_change_and_rejects_aliases() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        let file = root.join("archive.jet");
        fs::write(&file, b"keep-archive").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let m = fs::metadata(&file).unwrap();
        let scan = |hashes| {
            let mut out = Preserved {
                identities: BTreeMap::new(),
                sha256: BTreeMap::new(),
            };
            retained_walk(
                root,
                &file,
                &mut out,
                hashes,
                (m.dev(), m.uid(), m.gid()),
                0,
            )?;
            Ok::<_, anyhow::Error>(out)
        };
        let first = scan(true).unwrap();
        fs::write(&file, b"fail-archive").unwrap();
        assert_ne!(scan(true).unwrap().sha256, first.sha256);
        fs::remove_file(&file).unwrap();
        symlink("/etc/hosts", &file).unwrap();
        assert!(scan(true).is_err());
    }
    #[test]
    fn parent_symlink_is_not_accepted_for_regular_files() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("file"), b"evidence").unwrap();
        symlink(&real, d.path().join("alias")).unwrap();
        assert!(open_regular(&d.path().join("alias/file"), unsafe { libc::geteuid() }).is_err());
    }
    #[test]
    fn existing_lock_is_exclusive_and_preserved_without_replacement_or_truncation() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("existing.lock");
        fs::write(&path, b"retained lock content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let m = fs::metadata(&path).unwrap();
        let binding = LockBinding {
            path: path.clone(),
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: 0o600,
        };
        let held = hold_locks(std::slice::from_ref(&binding)).unwrap();
        assert!(hold_locks(std::slice::from_ref(&binding)).is_err());
        recheck_locks(std::slice::from_ref(&binding), &held).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"retained lock content");
        assert_eq!(fs::metadata(&path).unwrap().ino(), m.ino());
        drop(held);
        assert!(hold_locks(&[binding]).is_ok());
    }
    #[test]
    fn ancestor_replacement_is_detected_even_while_original_descriptors_survive() {
        let d = tempfile::tempdir().unwrap();
        let parent = d.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let held = hold_ancestors(&parent).unwrap();
        recheck_ancestors(&held).unwrap();
        fs::rename(&parent, d.path().join("old-parent")).unwrap();
        fs::create_dir(&parent).unwrap();
        assert!(recheck_ancestors(&held).is_err());
    }
}
