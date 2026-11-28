//! Bounded native discovery only. Returned paths carry no allocation authority.
//! The independently bounded common-time capture must reopen and validate them.
use super::*;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    ffi::{CStr, OsString},
    os::unix::ffi::OsStringExt,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Role {
    pub epoch: u64,
    pub root: PathBuf,
}
pub struct Limits {
    pub total_files: usize,
    pub entries_per_role: usize,
    pub directories_per_role: usize,
    pub timeout: Duration,
    pub minimum_file_bytes: u64,
    pub minimum_age_seconds: u64,
}
pub struct Discovery {
    pub selections: Vec<Selection>,
    pub inspected_entries: usize,
    pub opened_directories: usize,
    pub skipped_nonqualifying: usize,
    pub traversal_truncated: bool,
}
struct NativeDir(*mut libc::DIR);
impl NativeDir {
    fn new(file: &File) -> Result<Self> {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        ensure!(fd >= 0, "directory duplication failed");
        let ptr = unsafe { libc::fdopendir(fd) };
        if ptr.is_null() {
            unsafe { libc::close(fd) };
            anyhow::bail!("directory stream failed");
        }
        Ok(Self(ptr))
    }
    fn next(&mut self) -> Result<Option<OsString>> {
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                ensure!(
                    unsafe { *libc::__errno_location() } == 0,
                    "directory read failed"
                );
                return Ok(None);
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            ensure!(
                !name.is_empty() && !name.contains(&b'/'),
                "invalid native entry name"
            );
            return Ok(Some(OsString::from_vec(name.to_vec())));
        }
    }
}
impl Drop for NativeDir {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}
fn at(parent: &File, name: &OsStr) -> Result<libc::statx> {
    let name = CString::new(name.as_encoded_bytes())?;
    let mut sx = unsafe { std::mem::zeroed::<libc::statx>() };
    let mask = libc::STATX_BASIC_STATS | libc::STATX_BTIME | libc::STATX_MNT_ID;
    ensure!(
        unsafe {
            libc::statx(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                mask,
                &mut sx,
            )
        } == 0
            && sx.stx_mask & mask == mask,
        "entry changed or native identity unavailable"
    );
    Ok(sx)
}

/// Discovery is deliberately separate from allocation capture. A bounded subset
/// is sufficient, but a partial walk is disclosed, never represented as a full
/// physical ledger. Enumeration errors fail; excluded file types grant nothing.
pub fn discover(roles: &[Role], limits: &Limits) -> Result<Discovery> {
    ensure!(
        !roles.is_empty() && roles.len() <= 4,
        "bounded role set required"
    );
    ensure!(
        limits.total_files >= roles.len() && limits.total_files <= MAX_FILES,
        "file selection bound"
    );
    ensure!(
        limits.entries_per_role > 0 && limits.entries_per_role <= 1_000_000,
        "entry visit bound"
    );
    ensure!(
        limits.directories_per_role > 0 && limits.directories_per_role <= 1024,
        "directory traversal bound"
    );
    ensure!(
        !limits.timeout.is_zero() && limits.timeout <= Duration::from_secs(30),
        "selection deadline bound"
    );
    ensure!(
        limits.minimum_file_bytes > 0 && limits.minimum_age_seconds <= 3600,
        "minimum file eligibility"
    );
    let deadline = Instant::now() + limits.timeout;
    let at_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut epochs = BTreeSet::new();
    for (i, role) in roles.iter().enumerate() {
        components(&role.root)?;
        ensure!(
            role.root != Path::new("/")
                && [166, 167, 169, 170].contains(&role.epoch)
                && epochs.insert(role.epoch),
            "foreign/duplicate/root role"
        );
        for other in &roles[..i] {
            ensure!(
                !role.root.starts_with(&other.root) && !other.root.starts_with(&role.root),
                "overlapping roles"
            );
        }
    }
    let per_role = limits.total_files / roles.len();
    let mut result = Discovery {
        selections: Vec::new(),
        inspected_entries: 0,
        opened_directories: 0,
        skipped_nonqualifying: 0,
        traversal_truncated: false,
    };
    let mut expected_mount = None;
    for role in roles {
        let mut w = Window {
            directories: BTreeMap::new(),
            held: Vec::new(),
            seen: BTreeSet::new(),
            deadline,
        };
        w.directory(&role.root)?;
        let native = free(&w.directories[&role.root].file)?;
        let mount = (native.device, native.mount_id);
        if let Some(expected) = expected_mount {
            ensure!(mount == expected, "roles on different mounts");
        } else {
            expected_mount = Some(mount);
        }
        let mut queue = VecDeque::from([role.root.clone()]);
        let mut queued = BTreeSet::from([role.root.clone()]);
        let mut chosen: BinaryHeap<Reverse<(u64, PathBuf)>> = BinaryHeap::new();
        let mut visited = 0usize;
        while let Some(dir) = queue.pop_front() {
            w.check_time()?;
            if visited == limits.entries_per_role {
                result.traversal_truncated = true;
                break;
            }
            w.directory(&dir)?;
            let anchor = &w.directories[&dir];
            ensure!(
                (anchor.identity[0], anchor.mount_id) == mount,
                "directory mount changed"
            );
            result.opened_directories += 1;
            let mut entries = NativeDir::new(&anchor.file)?;
            while let Some(name) = entries.next()? {
                w.check_time()?;
                if visited == limits.entries_per_role {
                    result.traversal_truncated = true;
                    break;
                }
                visited += 1;
                result.inspected_entries += 1;
                let sx = at(&w.directories[&dir].file, &name)?;
                if sx.stx_mnt_id != native.mount_id {
                    result.skipped_nonqualifying += 1;
                    continue;
                }
                let path = dir.join(&name);
                let kind = u32::from(sx.stx_mode) & libc::S_IFMT;
                if kind == libc::S_IFDIR {
                    if queued.len() >= limits.directories_per_role {
                        result.traversal_truncated = true;
                        continue;
                    }
                    if queued.insert(path.clone()) {
                        queue.push_back(path);
                    }
                } else if kind == libc::S_IFREG && sx.stx_nlink == 1 {
                    let bytes = sx
                        .stx_blocks
                        .checked_mul(512)
                        .context("selection allocation overflow")?;
                    let time_ok = [sx.stx_mtime.tv_sec, sx.stx_ctime.tv_sec].iter().all(|t| {
                        u64::try_from(*t)
                            .ok()
                            .and_then(|t| at_seconds.checked_sub(t))
                            .is_some_and(|age| age >= limits.minimum_age_seconds)
                    });
                    if bytes < limits.minimum_file_bytes || !time_ok {
                        result.skipped_nonqualifying += 1;
                        continue;
                    }
                    if chosen.len() < per_role {
                        chosen.push(Reverse((bytes, path)));
                    } else if chosen
                        .peek()
                        .is_some_and(|old| (bytes, &path) > (old.0.0, &old.0.1))
                    {
                        chosen.pop();
                        chosen.push(Reverse((bytes, path)));
                    }
                } else {
                    result.skipped_nonqualifying += 1;
                }
            }
        }
        w.verify_directories()?;
        ensure!(
            !chosen.is_empty(),
            "no qualifying files for complete role set"
        );
        let mut files: Vec<_> = chosen.into_iter().map(|Reverse((_, p))| p).collect();
        files.sort();
        result.selections.push(Selection {
            epoch: role.epoch,
            root: role.root.clone(),
            files,
        });
    }
    ensure!(Instant::now() < deadline, "selection deadline expired");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write, os::unix::fs::symlink};
    fn write(p: &Path, n: usize) {
        let mut f = File::create(p).unwrap();
        f.write_all(&vec![1u8; n]).unwrap();
        f.sync_all().unwrap();
    }
    fn limits() -> Limits {
        Limits {
            total_files: 8,
            entries_per_role: 100,
            directories_per_role: 8,
            timeout: Duration::from_secs(5),
            minimum_file_bytes: 1,
            minimum_age_seconds: 0,
        }
    }
    #[test]
    fn bounded_largest_files_feed_actual_window_without_trusting_sizes() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        fs::create_dir(&root).unwrap();
        for (n, size) in [("small", 4096), ("medium", 8192), ("large", 32768)] {
            write(&root.join(n), size);
        }
        let roles = [Role {
            epoch: 170,
            root: root.clone(),
        }];
        let mut l = limits();
        l.total_files = 2;
        let found = discover(&roles, &l).unwrap();
        assert!(!found.traversal_truncated);
        assert_eq!(found.inspected_entries, 3);
        assert_eq!(
            found.selections[0].files,
            vec![root.join("large"), root.join("medium")]
        );
        let actual = capture(t.path(), &found.selections, Duration::from_secs(5), || {
            Ok(())
        })
        .unwrap();
        assert_eq!(actual.current_unique_bytes()[&170], 40960);
        actual.revalidate().unwrap();
    }
    #[test]
    fn symlinks_hardlinks_and_sparse_logical_sizes_do_not_win_selection() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        fs::create_dir(&root).unwrap();
        let good = root.join("good");
        write(&good, 16384);
        let sparse = root.join("sparse");
        File::create(&sparse).unwrap().set_len(8 << 20).unwrap();
        symlink(&good, root.join("alias")).unwrap();
        symlink(t.path(), root.join("parent")).unwrap();
        let linked = root.join("linked");
        write(&linked, 65536);
        fs::hard_link(&linked, root.join("linked2")).unwrap();
        let found = discover(&[Role { epoch: 166, root }], &limits()).unwrap();
        assert_eq!(found.selections[0].files, vec![good]);
        assert!(found.skipped_nonqualifying >= 5);
    }
    #[test]
    fn discovery_does_not_authorize_replaced_members() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("selected");
        write(&path, 16384);
        let found = discover(
            &[Role {
                epoch: 167,
                root: t.path().into(),
            }],
            &limits(),
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        symlink("/etc/passwd", &path).unwrap();
        assert!(
            capture(t.path(), &found.selections, Duration::from_secs(5), || Ok(
                ()
            ))
            .is_err()
        );
    }
    #[test]
    fn traversal_bound_is_disclosed_and_subset_is_still_validated() {
        let t = tempfile::tempdir().unwrap();
        write(&t.path().join("root-file"), 8192);
        for i in 0..10 {
            let p = t.path().join(format!("dir{i}"));
            fs::create_dir(&p).unwrap();
            write(&p.join("child"), 16384);
        }
        let mut l = limits();
        l.directories_per_role = 1;
        let found = discover(
            &[Role {
                epoch: 169,
                root: t.path().into(),
            }],
            &l,
        )
        .unwrap();
        assert!(found.traversal_truncated);
        assert_eq!(found.opened_directories, 1);
        assert_eq!(found.selections[0].files.len(), 1);
        capture(t.path(), &found.selections, Duration::from_secs(5), || {
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn empty_old_enough_foreign_duplicate_and_overlapping_roles_fail() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("file");
        write(&p, 8192);
        let mut l = limits();
        l.minimum_age_seconds = 3600;
        assert!(
            discover(
                &[Role {
                    epoch: 166,
                    root: t.path().into()
                }],
                &l
            )
            .is_err()
        );
        for e in [165, 200] {
            assert!(
                discover(
                    &[Role {
                        epoch: e,
                        root: t.path().into()
                    }],
                    &limits()
                )
                .is_err()
            );
        }
        assert!(
            discover(
                &[
                    Role {
                        epoch: 166,
                        root: t.path().into()
                    },
                    Role {
                        epoch: 166,
                        root: t.path().join("child")
                    }
                ],
                &limits()
            )
            .is_err()
        );
        assert!(
            discover(
                &[
                    Role {
                        epoch: 166,
                        root: t.path().into()
                    },
                    Role {
                        epoch: 167,
                        root: t.path().join("child")
                    }
                ],
                &limits()
            )
            .is_err()
        );
        assert!(
            discover(
                &[Role {
                    epoch: 166,
                    root: PathBuf::from("/proc")
                }],
                &limits()
            )
            .is_err()
        );
    }
    #[test]
    fn role_file_budget_and_deadlines_are_enforced_before_enumeration() {
        let t = tempfile::tempdir().unwrap();
        write(&t.path().join("file"), 8192);
        let roles = [Role {
            epoch: 170,
            root: t.path().into(),
        }];
        let mut l = limits();
        l.total_files = MAX_FILES + 1;
        assert!(discover(&roles, &l).is_err());
        l = limits();
        l.timeout = Duration::ZERO;
        assert!(discover(&roles, &l).is_err());
        l = limits();
        l.entries_per_role = 1_000_001;
        assert!(discover(&roles, &l).is_err());
    }
}
