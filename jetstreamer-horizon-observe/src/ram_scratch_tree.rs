//! Descriptor-relative retirement primitive. This module is not a launcher or
//! standalone retirement authority; its caller must bind terminal ownership,
//! retained artifacts, mount identity, process references and durable intent.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        ffi::CString,
        fs::{self, File},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
    },
};

/// File identity pinned before any destructive operation. Directory clocks and
/// sizes are omitted because removing children legitimately changes them.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub(crate) struct Entry {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    directory: bool,
    size: u64,
    mtime: i64,
    mtime_nanos: i64,
    ctime: i64,
    ctime_nanos: i64,
}
pub(crate) type Ledger = BTreeMap<String, Entry>;

fn entry(m: &fs::Metadata, device: u64, uid: u32, gid: u32) -> Result<Entry> {
    ensure!(
        m.dev() == device
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o077 == 0
            && (m.is_file() || m.is_dir())
            && (!m.is_file() || m.nlink() == 1),
        "scratch contains a foreign owner/device, link or special entry"
    );
    Ok(Entry {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        directory: m.is_dir(),
        size: if m.is_dir() { 0 } else { m.len() },
        mtime: if m.is_dir() { 0 } else { m.mtime() },
        mtime_nanos: if m.is_dir() { 0 } else { m.mtime_nsec() },
        ctime: if m.is_dir() { 0 } else { m.ctime() },
        ctime_nanos: if m.is_dir() { 0 } else { m.ctime_nsec() },
    })
}

pub(crate) fn open_root(path: &Path, device: u64, inode: u64) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "scratch root is not canonical"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        file.metadata()?.dev() == device && file.metadata()?.ino() == inode,
        "scratch root identity changed"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "scratch retirement already locked"
    );
    Ok(file)
}

fn open_child(parent: &File, name: &str, flags: i32) -> Result<File> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "invalid child name"
    );
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot open scratch child");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn children(parent: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? {
        names.push(
            item?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 scratch child"))?,
        );
        ensure!(
            names.len() <= 100_000,
            "scratch directory exceeds retirement budget"
        );
    }
    names.sort();
    Ok(names)
}

fn capture_at(
    parent: &File,
    prefix: &str,
    out: &mut Ledger,
    device: u64,
    uid: u32,
    gid: u32,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 128, "scratch tree nesting exceeds bound");
    for name in children(parent)? {
        let fd = open_child(parent, &name, libc::O_PATH)?;
        let identity = entry(&fd.metadata()?, device, uid, gid)?;
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        ensure!(
            relative.len() <= 4096,
            "scratch relative path exceeds bound"
        );
        ensure!(
            out.len() < 100_000,
            "scratch tree exceeds retirement entry budget"
        );
        out.insert(relative.clone(), identity.clone());
        if identity.directory {
            let dir = open_child(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            ensure!(
                entry(&dir.metadata()?, device, uid, gid)? == identity,
                "scratch child changed while opened"
            );
            capture_at(&dir, &relative, out, device, uid, gid, depth + 1)?;
        }
    }
    Ok(())
}

pub(crate) fn capture(root: &File, device: u64, uid: u32, gid: u32) -> Result<Ledger> {
    let mut ledger = BTreeMap::new();
    ledger.insert(String::new(), entry(&root.metadata()?, device, uid, gid)?);
    capture_at(root, "", &mut ledger, device, uid, gid, 0)?;
    Ok(ledger)
}

pub(crate) fn validate_remaining(
    expected: &Ledger,
    current: &Ledger,
    resuming: bool,
) -> Result<()> {
    ensure!(expected.get("") == current.get(""), "scratch root replaced");
    if !resuming {
        ensure!(
            current == expected,
            "scratch changed after check-only qualification"
        );
    }
    for (path, identity) in current {
        ensure!(
            expected.get(path) == Some(identity),
            "replacement or unexpected scratch entry: {path}"
        );
    }
    Ok(())
}

fn remove_at(
    parent: &File,
    prefix: &str,
    expected: &Ledger,
    device: u64,
    uid: u32,
    gid: u32,
    depth: usize,
) -> Result<u64> {
    ensure!(depth <= 128, "scratch deletion depth exceeds bound");
    let mut removed = 0;
    for name in children(parent)? {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let fd = open_child(parent, &name, libc::O_PATH)?;
        let observed = entry(&fd.metadata()?, device, uid, gid)?;
        ensure!(
            expected.get(&relative) == Some(&observed),
            "scratch entry replaced before unlink"
        );
        if observed.directory {
            let dir = open_child(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            ensure!(
                entry(&dir.metadata()?, device, uid, gid)? == observed,
                "scratch directory replaced"
            );
            removed += remove_at(&dir, &relative, expected, device, uid, gid, depth + 1)?;
            dir.sync_all()?;
        }
        let last = open_child(parent, &name, libc::O_PATH)?;
        ensure!(
            entry(&last.metadata()?, device, uid, gid)? == observed,
            "scratch entry changed at unlink"
        );
        let name = CString::new(name)?;
        ensure!(
            unsafe {
                libc::unlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    if observed.directory {
                        libc::AT_REMOVEDIR
                    } else {
                        0
                    },
                )
            } == 0,
            "scratch unlink failed: {}",
            std::io::Error::last_os_error()
        );
        parent.sync_all()?;
        removed += 1;
    }
    Ok(removed)
}

pub(crate) fn remove_contents(
    root: &File,
    expected: &Ledger,
    device: u64,
    uid: u32,
    gid: u32,
) -> Result<u64> {
    let current = capture(root, device, uid, gid)?;
    validate_remaining(expected, &current, true)?;
    let removed = remove_at(root, "", expected, device, uid, gid, 0)?;
    root.sync_all()?;
    ensure!(
        children(root)?.is_empty(),
        "scratch is not empty after scoped retirement"
    );
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn fixture() -> (tempfile::TempDir, File, u64, u32, u32) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let m = fs::metadata(temp.path()).unwrap();
        let root = open_root(temp.path(), m.dev(), m.ino()).unwrap();
        (temp, root, m.dev(), m.uid(), m.gid())
    }
    fn write(path: &Path) {
        fs::write(path, b"disposable bounded benchmark state").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn descriptor_relative_retirement_preserves_root_and_unrelated_sibling() {
        let (temp, root, dev, uid, gid) = fixture();
        let sibling = tempfile::tempdir().unwrap();
        write(&sibling.path().join("preserve"));
        let before = root.metadata().unwrap().ino();
        fs::create_dir(temp.path().join("nested")).unwrap();
        fs::set_permissions(
            temp.path().join("nested"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write(&temp.path().join("nested/state"));
        let expected = capture(&root, dev, uid, gid).unwrap();
        assert_eq!(remove_contents(&root, &expected, dev, uid, gid).unwrap(), 2);
        assert_eq!(root.metadata().unwrap().ino(), before);
        assert!(temp.path().is_dir());
        assert_eq!(
            fs::read(sibling.path().join("preserve")).unwrap(),
            b"disposable bounded benchmark state"
        );
    }
    #[test]
    fn symlink_hardlink_and_foreign_device_are_not_retirement_targets() {
        let (temp, root, dev, uid, gid) = fixture();
        symlink("/", temp.path().join("escape")).unwrap();
        assert!(capture(&root, dev, uid, gid).is_err());
        fs::remove_file(temp.path().join("escape")).unwrap();
        write(&temp.path().join("state"));
        fs::hard_link(temp.path().join("state"), temp.path().join("alias")).unwrap();
        assert!(capture(&root, dev, uid, gid).is_err());
        assert!(capture(&root, dev + 1, uid, gid).is_err());
    }
    #[test]
    fn interrupted_retirement_accepts_absence_but_rejects_new_or_replaced_entries() {
        let (temp, root, dev, uid, gid) = fixture();
        write(&temp.path().join("first"));
        write(&temp.path().join("second"));
        let expected = capture(&root, dev, uid, gid).unwrap();
        fs::remove_file(temp.path().join("first")).unwrap();
        let current = capture(&root, dev, uid, gid).unwrap();
        validate_remaining(&expected, &current, true).unwrap();
        assert!(validate_remaining(&expected, &current, false).is_err());
        assert_eq!(remove_contents(&root, &expected, dev, uid, gid).unwrap(), 1);
        write(&temp.path().join("new"));
        assert!(remove_contents(&root, &expected, dev, uid, gid).is_err());
    }
    #[test]
    fn replacement_inode_or_bytes_cannot_hide_behind_same_name() {
        let (temp, root, dev, uid, gid) = fixture();
        write(&temp.path().join("state"));
        let expected = capture(&root, dev, uid, gid).unwrap();
        fs::rename(temp.path().join("state"), temp.path().join("old")).unwrap();
        write(&temp.path().join("state"));
        assert!(remove_contents(&root, &expected, dev, uid, gid).is_err());
    }
}
