//! Current lower-bound allocation integrity proof inside a fresh admission.
use super::*;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::Instant;

const LIMIT: usize = 8_000_000;
#[derive(Clone, Debug)]
struct Entry {
    dev: u64,
    ino: u64,
    mode: u32,
    bytes: u64,
    len: u64,
}
fn entry(m: &fs::Metadata) -> Result<Entry> {
    ensure!(
        m.is_dir() || m.is_file(),
        "allocation proof rejects symlinks and special files"
    );
    ensure!(
        !m.is_file() || m.nlink() == 1,
        "allocation proof rejects shared hardlinks"
    );
    Ok(Entry {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        bytes: m
            .blocks()
            .checked_mul(512)
            .context("allocation block overflow")?,
        len: m.len(),
    })
}
fn same(a: &Entry, b: &Entry) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.mode == b.mode
}
fn opened(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(name.as_bytes())?;
    let flags = if directory {
        libc::O_RDONLY | libc::O_DIRECTORY
    } else {
        libc::O_PATH
    };
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(
        fd >= 0,
        "allocation descriptor open failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn chain(path: &Path) -> Result<Vec<File>> {
    ensure!(path.is_absolute(), "allocation root must be absolute");
    let mut chain = vec![
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?,
    ];
    for part in path.components() {
        match part {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let next = opened(chain.last().unwrap(), name, true)?;
                chain.push(next);
            }
            _ => bail!("allocation root contains a noncanonical component"),
        }
    }
    Ok(chain)
}
fn filesystem(magic: i64) -> Result<()> {
    // Linux ext2/3/4 currently has no reflink/shared-extent feature. XFS,
    // Btrfs, overlay and all unknown/future profiles deliberately fail closed.
    ensure!(
        magic == 0xef53,
        "allocation proof requires the closed non-reflink ext filesystem profile"
    );
    Ok(())
}
fn mount(fd: &File) -> Result<u64> {
    fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?
        .lines()
        .find_map(|l| {
            l.strip_prefix("mnt_id:")
                .and_then(|v| v.trim().parse().ok())
        })
        .context("allocation descriptor mount identity missing")
}
fn profile(fd: &File, dev: u64, mount_id: u64, enforce_fs: bool) -> Result<()> {
    ensure!(
        fd.metadata()?.dev() == dev && mount(fd)? == mount_id,
        "allocation proof crossed mount/device boundary"
    );
    if enforce_fs {
        let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(fd.as_raw_fd(), s.as_mut_ptr()) } == 0,
            "allocation fstatfs failed"
        );
        filesystem(unsafe { s.assume_init() }.f_type)?;
    }
    Ok(())
}
struct Scope {
    dev: u64,
    mount_id: u64,
    deadline: Instant,
    enforce_fs: bool,
}
fn walk(
    fd: &File,
    path: &Path,
    scope: &Scope,
    entries: &mut BTreeMap<PathBuf, Entry>,
    dirs: &mut BTreeSet<(u64, u64)>,
) -> Result<()> {
    let Scope {
        dev,
        mount_id,
        deadline,
        enforce_fs,
    } = *scope;
    ensure!(
        entries.len() < LIMIT && path.components().count() <= 128 && Instant::now() < deadline,
        "allocation scan entry/depth/time bound exceeded"
    );
    profile(fd, dev, mount_id, enforce_fs)?;
    let initial = entry(&fd.metadata()?)?;
    ensure!(
        dirs.insert((initial.dev, initial.ino)),
        "allocation duplicate directory alias"
    );
    ensure!(
        entries.insert(path.into(), initial.clone()).is_none(),
        "allocation duplicate path"
    );
    for item in fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))? {
        ensure!(
            entries.len() < LIMIT && Instant::now() < deadline,
            "allocation scan bound exceeded"
        );
        let name = item?.file_name();
        let handle = opened(fd, &name, false)?;
        profile(&handle, dev, mount_id, enforce_fs)?;
        let m = handle.metadata()?;
        let e = entry(&m)?;
        let child = path.join(&name);
        if m.is_dir() {
            let directory = opened(fd, &name, true)?;
            ensure!(
                same(&e, &entry(&directory.metadata()?)?),
                "allocation directory identity changed at open"
            );
            walk(&directory, &child, scope, entries, dirs)?;
        } else {
            ensure!(
                entries.insert(child, e).is_none(),
                "allocation duplicate file path"
            );
        }
    }
    ensure!(
        same(&initial, &entry(&fd.metadata()?)?),
        "allocation directory identity changed during scan"
    );
    Ok(())
}
fn lower(first: &BTreeMap<PathBuf, Entry>, second: &BTreeMap<PathBuf, Entry>) -> Result<u64> {
    ensure!(
        first.keys().eq(second.keys()),
        "allocation path census changed between passes"
    );
    first.iter().try_fold(0u64, |total, (path, a)| {
        let b = &second[path];
        ensure!(
            same(a, b) && b.bytes >= a.bytes && b.len >= a.len,
            "allocation identity/size shrank or changed between passes"
        );
        total
            .checked_add(a.bytes.min(b.bytes))
            .context("allocation total overflow")
    })
}
fn observe_inner(
    path: &Path,
    enforce_fs: bool,
    recheck: impl FnOnce() -> Result<()>,
) -> Result<Value> {
    let anchors = chain(path)?;
    let root = anchors
        .last()
        .context("allocation root descriptor missing")?;
    let original = entry(&root.metadata()?)?;
    let mount_id = mount(root)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let scope = Scope {
        dev: original.dev,
        mount_id,
        deadline,
        enforce_fs,
    };
    let mut first = BTreeMap::new();
    let mut second = BTreeMap::new();
    walk(
        root,
        Path::new(""),
        &scope,
        &mut first,
        &mut BTreeSet::new(),
    )?;
    walk(
        root,
        Path::new(""),
        &scope,
        &mut second,
        &mut BTreeSet::new(),
    )?;
    let bytes = lower(&first, &second)?;
    recheck()?; // All original descriptors remain alive through final owner check.
    let current = chain(path)?;
    ensure!(
        anchors.len() == current.len(),
        "allocation ancestor chain changed"
    );
    for (a, b) in anchors.iter().zip(&current) {
        ensure!(
            same(&entry(&a.metadata()?)?, &entry(&b.metadata()?)?),
            "allocation root/ancestor identity changed"
        );
    }
    profile(root, original.dev, mount_id, enforce_fs)?;
    Ok(
        json!({"schema":"jetstreamer-canary227-current-allocation-v1","root":path,
        "device":original.dev,"inode":original.ino,"mount_id":mount_id,"filesystem_profile":"linux-ext-nonreflink-v1",
        "passes":2,"entries":first.len(),"allocation_lower_bound_bytes":bytes,
        "regular_hardlinks_rejected":true,"symlinks_rejected":true,"owner_rechecked_with_descriptors_held":true}),
    )
}
pub(super) fn observe(path: &Path, recheck: impl FnOnce() -> Result<()>) -> Result<Value> {
    observe_inner(path, true, recheck)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn closed_filesystem_profile_rejects_reflink_and_unknown_types() {
        filesystem(0xef53).unwrap();
        for magic in [0, 0x58465342, 0x9123683e, 0x794c7630] {
            assert!(filesystem(magic).is_err());
        }
    }
    #[test]
    fn ordinary_tree_and_zero_file_have_definite_allocation() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("zero"), []).unwrap();
        let p = observe_inner(d.path(), false, || Ok(())).unwrap();
        assert!(p["allocation_lower_bound_bytes"].as_u64().is_some());
        assert_eq!(p["passes"], 2);
    }
    #[test]
    fn intra_and_cross_root_hardlinks_and_symlinks_are_rejected() {
        for outside in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let other = tempfile::tempdir().unwrap();
            fs::write(d.path().join("a"), b"payload").unwrap();
            fs::hard_link(
                d.path().join("a"),
                if outside {
                    other.path().join("b")
                } else {
                    d.path().join("b")
                },
            )
            .unwrap();
            assert!(observe_inner(d.path(), false, || Ok(())).is_err());
        }
        let d = tempfile::tempdir().unwrap();
        symlink("/", d.path().join("alias")).unwrap();
        assert!(observe_inner(d.path(), false, || Ok(())).is_err());
        let a = tempfile::tempdir().unwrap();
        symlink(d.path(), a.path().join("ancestor")).unwrap();
        assert!(observe_inner(&a.path().join("ancestor"), false, || Ok(())).is_err());
    }
    #[test]
    fn root_or_ancestor_replacement_during_owner_recheck_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("root");
        fs::create_dir(&root).unwrap();
        assert!(
            observe_inner(&root, false, || {
                fs::rename(&root, d.path().join("old"))?;
                fs::create_dir(&root)?;
                Ok(())
            })
            .is_err()
        );
        let parent = d.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(parent.join("root")).unwrap();
        assert!(
            observe_inner(&parent.join("root"), false, || {
                fs::rename(&parent, d.path().join("old-parent"))?;
                symlink(d.path().join("old-parent"), &parent)?;
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn identity_shrink_census_churn_and_overflow_fail_closed() {
        let a = Entry {
            dev: 1,
            ino: 2,
            mode: 0o100600,
            bytes: 0,
            len: 0,
        };
        let first = BTreeMap::from([(PathBuf::from("a"), a.clone())]);
        assert_eq!(lower(&first, &first).unwrap(), 0);
        let mut changed = first.clone();
        changed.get_mut(Path::new("a")).unwrap().ino = 3;
        assert!(lower(&first, &changed).is_err());
        let mut big = first.clone();
        big.get_mut(Path::new("a")).unwrap().bytes = 512;
        assert!(lower(&big, &first).is_err());
        assert!(lower(&first, &BTreeMap::new()).is_err());
        let mut overflow = first;
        overflow.get_mut(Path::new("a")).unwrap().bytes = u64::MAX;
        overflow.insert("b".into(), Entry { bytes: 1, ..a });
        assert!(lower(&overflow, &overflow).is_err());
    }
}
