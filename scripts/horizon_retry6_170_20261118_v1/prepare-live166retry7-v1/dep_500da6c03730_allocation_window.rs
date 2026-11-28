//! Native allocation window for a future admission adapter. No launcher, receipt
//! importer, remote client or capacity-authorizing entry point is provided here.
//! All credited descriptors remain open across the shared free-space midpoint.
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::{File, Metadata, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

pub const MAX_FILES: usize = 32_768;
pub const MAX_DIRECTORIES: usize = 8_192;
pub const LANE_CAP: u64 = 309_237_645_312;
#[path = "dep_dacef71fa297_selection.rs"]
mod selection;
pub use selection::{Discovery, Limits, Role, discover};

pub struct Selection {
    pub epoch: u64,
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFact {
    pub epoch: u64,
    pub path: PathBuf,
    pub identity: [u64; 12],
    pub birth: (i64, u32),
    pub mount_id: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreePoint {
    pub device: u64,
    pub mount_id: u64,
    pub available_bytes: u64,
}
// No Deserialize: a serialized observation cannot construct a native window.
pub struct Observation {
    files: Vec<FileFact>,
    current_unique_bytes: BTreeMap<u64, u64>,
    before: FreePoint,
    midpoint: FreePoint,
    after: FreePoint,
    conservative_available_bytes: u64,
    elapsed: Duration,
    // Private live handles prevent callers from constructing a native result
    // from deserialized facts and retain custody until the enclosing decision.
    window: Window,
}
impl Observation {
    pub fn files(&self) -> &[FileFact] {
        &self.files
    }
    pub fn current_unique_bytes(&self) -> &BTreeMap<u64, u64> {
        &self.current_unique_bytes
    }
    pub fn free_points(&self) -> (&FreePoint, &FreePoint, &FreePoint) {
        (&self.before, &self.midpoint, &self.after)
    }
    pub fn conservative_available_bytes(&self) -> u64 {
        self.conservative_available_bytes
    }
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }
    /// Recheck discovery eligibility on the exact captured baseline, not a stale path.
    pub fn require_minimum_age(&self, at_seconds: u64, minimum_age_seconds: u64) -> Result<()> {
        ensure!(
            minimum_age_seconds > 0 && minimum_age_seconds <= 3600,
            "bounded baseline age"
        );
        let cutoff = at_seconds
            .checked_sub(minimum_age_seconds)
            .context("baseline age clock")?;
        for f in &self.files {
            ensure!(
                f.identity[8] <= cutoff && f.identity[10] <= cutoff,
                "captured allocation baseline is too recent: epoch={} path={}",
                f.epoch,
                f.path.display()
            );
        }
        Ok(())
    }
    pub fn revalidate(&self) -> Result<()> {
        self.window.verify_directories()?;
        for held in &self.window.held {
            self.window.check_time()?;
            let f = &held.fact;
            let reopened = open_at(
                &self.window.directories[f.path.parent().context("file parent")?].file,
                f.path.file_name().context("file leaf")?,
                false,
            )?;
            unchanged(f, &held.file, &reopened, "before enclosing decision")?;
        }
        Ok(())
    }
}
struct Directory {
    file: File,
    identity: [u64; 5],
    mount_id: u64,
}
struct Held {
    file: File,
    fact: FileFact,
}
struct Window {
    directories: BTreeMap<PathBuf, Directory>,
    held: Vec<Held>,
    seen: BTreeSet<(u64, u64)>,
    deadline: Instant,
}

fn components(path: &Path) -> Result<Vec<&OsStr>> {
    ensure!(path.is_absolute(), "absolute path required");
    let mut names = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(s) => names.push(s),
            _ => anyhow::bail!("noncanonical component"),
        }
    }
    ensure!(names.len() <= 64, "path depth bound");
    let canonical = names.iter().fold(PathBuf::from("/"), |mut p, n| {
        p.push(n);
        p
    });
    ensure!(
        canonical.as_os_str() == path.as_os_str(),
        "noncanonical spelling"
    );
    Ok(names)
}
fn open_at(parent: &File, name: &OsStr, directory: bool) -> Result<File> {
    let name = CString::new(name.as_encoded_bytes())?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if directory {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    ensure!(
        fd >= 0,
        "no-follow open failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn statx(file: &File) -> Result<libc::statx> {
    let mut s = unsafe { std::mem::zeroed::<libc::statx>() };
    let empty = c"";
    let mask = libc::STATX_BASIC_STATS | libc::STATX_BTIME | libc::STATX_MNT_ID;
    ensure!(
        unsafe {
            libc::statx(
                file.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                mask,
                &mut s,
            )
        } == 0
            && s.stx_mask & mask == mask,
        "native identity/birth/mount facts unavailable"
    );
    Ok(s)
}
fn dir_identity(m: &Metadata) -> [u64; 5] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
    ]
}
fn identity(m: &Metadata) -> [u64; 12] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        m.blocks(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}
fn fact(file: &File, path: &Path, epoch: u64) -> Result<FileFact> {
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1,
        "only single-linked regular files qualify"
    );
    let sx = statx(file)?;
    ensure!(
        sx.stx_ino == m.ino()
            && sx.stx_size == m.len()
            && sx.stx_blocks == m.blocks()
            && u64::from(sx.stx_nlink) == m.nlink()
            && sx.stx_uid == m.uid()
            && sx.stx_gid == m.gid()
            && u32::from(sx.stx_mode) == m.mode()
            && sx.stx_mtime.tv_sec == m.mtime()
            && i64::from(sx.stx_mtime.tv_nsec) == m.mtime_nsec()
            && sx.stx_ctime.tv_sec == m.ctime()
            && i64::from(sx.stx_ctime.tv_nsec) == m.ctime_nsec(),
        "stat/statx race"
    );
    ensure!(identity(&m) == identity(&file.metadata()?), "capture race");
    Ok(FileFact {
        epoch,
        path: path.into(),
        identity: identity(&m),
        birth: (sx.stx_btime.tv_sec, sx.stx_btime.tv_nsec),
        mount_id: sx.stx_mnt_id,
    })
}
fn unchanged(first: &FileFact, held: &File, reopened: &File, phase: &str) -> Result<()> {
    let retained = fact(held, &first.path, first.epoch).with_context(|| {
        format!(
            "retained fact failed epoch={} path={}",
            first.epoch,
            first.path.display()
        )
    })?;
    let current = fact(reopened, &first.path, first.epoch).with_context(|| {
        format!(
            "reopened fact failed epoch={} path={}",
            first.epoch,
            first.path.display()
        )
    })?;
    ensure!(
        *first == retained && *first == current,
        "file allocation/path changed {phase}: epoch={} path={} before={:?} held={:?} reopened={:?}",
        first.epoch,
        first.path.display(),
        first,
        retained,
        current
    );
    Ok(())
}

fn free(file: &File) -> Result<FreePoint> {
    let mut sf = unsafe { std::mem::zeroed::<libc::statfs>() };
    let mut sv = unsafe { std::mem::zeroed::<libc::statvfs>() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut sf) } == 0
            && unsafe { libc::fstatvfs(file.as_raw_fd(), &mut sv) } == 0,
        "native filesystem query failed"
    );
    ensure!(
        sf.f_type == 0xEF53 && sv.f_frsize > 0,
        "only qualified ext filesystem without shared extents"
    );
    Ok(FreePoint {
        device: file.metadata()?.dev(),
        mount_id: statx(file)?.stx_mnt_id,
        available_bytes: sv
            .f_bavail
            .checked_mul(sv.f_frsize)
            .context("free-space overflow")?,
    })
}
impl Window {
    fn check_time(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "allocation window deadline exceeded"
        );
        Ok(())
    }
    fn directory(&mut self, path: &Path) -> Result<()> {
        self.check_time()?;
        let names = components(path)?;
        let mut current = PathBuf::from("/");
        if !self.directories.contains_key(&current) {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")?;
            self.directories.insert(
                current.clone(),
                Directory {
                    identity: dir_identity(&file.metadata()?),
                    mount_id: statx(&file)?.stx_mnt_id,
                    file,
                },
            );
        }
        for name in names {
            self.check_time()?;
            let next = current.join(name);
            if !self.directories.contains_key(&next) {
                ensure!(
                    self.directories.len() < MAX_DIRECTORIES,
                    "directory descriptor bound"
                );
                let file = open_at(&self.directories[&current].file, name, true)?;
                let m = file.metadata()?;
                ensure!(m.is_dir(), "non-directory ancestor");
                self.directories.insert(
                    next.clone(),
                    Directory {
                        identity: dir_identity(&m),
                        mount_id: statx(&file)?.stx_mnt_id,
                        file,
                    },
                );
            }
            current = next;
        }
        Ok(())
    }
    fn verify_directories(&self) -> Result<()> {
        for (path, old) in &self.directories {
            self.check_time()?;
            let reopened = if path == Path::new("/") {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open("/")?
            } else {
                open_at(
                    &self.directories[path.parent().context("directory parent")?].file,
                    path.file_name().context("directory leaf")?,
                    true,
                )?
            };
            for f in [&old.file, &reopened] {
                ensure!(
                    dir_identity(&f.metadata()?) == old.identity
                        && statx(f)?.stx_mnt_id == old.mount_id,
                    "directory replaced or owner/mount changed"
                );
            }
        }
        Ok(())
    }
}

/// Capture explicitly selected native files across one common free-space point.
/// The caller must authenticate the complete candidate/peer set, actual process
/// identities, guard/admission lineage and mutation exclusion. `midpoint_action`
/// is for that enclosing native transaction; it cannot provide allocation facts.
/// Changed captured identity/allocation/timestamp facts reject the whole window.
/// This is physical accounting, not content authentication or continuous writer exclusion.
/// A later generation may select a different subset in a new complete transaction.
pub fn capture<F>(
    filesystem: &Path,
    selections: &[Selection],
    timeout: Duration,
    midpoint_action: F,
) -> Result<Observation>
where
    F: FnOnce() -> Result<()>,
{
    ensure!(
        !selections.is_empty() && selections.len() <= 4,
        "bounded explicit role set"
    );
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(30),
        "bounded native window"
    );
    let started = Instant::now();
    let mut w = Window {
        directories: BTreeMap::new(),
        held: Vec::new(),
        seen: BTreeSet::new(),
        deadline: started + timeout,
    };
    let mut epochs = BTreeSet::new();
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut count = 0usize;
    for s in selections {
        components(&s.root)?;
        ensure!(
            s.root != Path::new("/")
                && [166, 167, 169, 170].contains(&s.epoch)
                && epochs.insert(s.epoch),
            "foreign/duplicate/root role"
        );
        ensure!(!s.files.is_empty(), "empty role subset");
        for root in &roots {
            ensure!(
                !s.root.starts_with(root) && !Path::new(root).starts_with(&s.root),
                "overlapping role roots"
            );
        }
        roots.push(s.root.clone());
        count = count
            .checked_add(s.files.len())
            .context("selection overflow")?;
        ensure!(count <= MAX_FILES, "file descriptor bound");
    }
    w.directory(filesystem)?;
    let before = free(&w.directories[filesystem].file)?;
    for s in selections {
        w.directory(&s.root)?;
        let root = &w.directories[&s.root];
        ensure!(
            root.identity[0] == before.device && root.mount_id == before.mount_id,
            "foreign role mount"
        );
        for path in &s.files {
            w.check_time()?;
            components(path)?;
            ensure!(
                path.starts_with(&s.root) && path != &s.root,
                "file outside exact role root"
            );
            let parent = path.parent().context("file parent")?;
            w.directory(parent)?;
            for p in parent.ancestors().take_while(|p| p.starts_with(&s.root)) {
                let a = &w.directories[p];
                ensure!(
                    a.identity[0] == before.device && a.mount_id == before.mount_id,
                    "nested mount not qualified"
                );
            }
            let file = open_at(
                &w.directories[parent].file,
                path.file_name().context("file leaf")?,
                false,
            )?;
            let f = fact(&file, path, s.epoch)?;
            ensure!(
                f.identity[0] == before.device
                    && f.mount_id == before.mount_id
                    && w.seen.insert((f.identity[0], f.identity[1])),
                "foreign or repeated allocation"
            );
            w.held.push(Held { file, fact: f });
        }
    }
    w.verify_directories()?;
    midpoint_action()?;
    w.check_time()?;
    let midpoint = free(&w.directories[filesystem].file)?;
    let mut totals = BTreeMap::new();
    for held in &w.held {
        w.check_time()?;
        let first = &held.fact;
        let path = &first.path;
        let reopened = open_at(
            &w.directories[path.parent().context("file parent")?].file,
            path.file_name().context("file leaf")?,
            false,
        )?;
        unchanged(first, &held.file, &reopened, "across midpoint")?;
        let bytes = first.identity[7]
            .checked_mul(512)
            .context("allocation overflow")?;
        let total = totals.entry(first.epoch).or_insert(0u64);
        *total = total
            .checked_add(bytes)
            .context("role allocation overflow")?;
        ensure!(*total < LANE_CAP, "unchanged lane cap exhausted");
    }
    w.verify_directories()?;
    let after = free(&w.directories[filesystem].file)?;
    w.check_time()?;
    ensure!(
        before.device == midpoint.device
            && before.device == after.device
            && before.mount_id == midpoint.mount_id
            && before.mount_id == after.mount_id,
        "filesystem changed"
    );
    ensure!(
        totals.len() == selections.len() && totals.values().all(|n| *n > 0),
        "zero credited role"
    );
    Ok(Observation {
        files: w.held.iter().map(|h| h.fact.clone()).collect(),
        current_unique_bytes: totals,
        conservative_available_bytes: before
            .available_bytes
            .min(midpoint.available_bytes)
            .min(after.available_bytes),
        before,
        midpoint,
        after,
        elapsed: started.elapsed(),
        window: w,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{PermissionsExt, symlink},
    };
    fn fixture() -> (tempfile::TempDir, Vec<Selection>) {
        let t = tempfile::tempdir().unwrap();
        let mut selections = Vec::new();
        for epoch in [166, 167, 169, 170] {
            let root = t.path().join(epoch.to_string());
            fs::create_dir(&root).unwrap();
            let path = root.join("allocated");
            let mut f = File::create(&path).unwrap();
            f.write_all(&[7u8; 16384]).unwrap();
            f.sync_all().unwrap();
            selections.push(Selection {
                epoch,
                root,
                files: vec![path],
            });
        }
        (t, selections)
    }
    fn run<F: FnOnce() -> Result<()>>(
        t: &tempfile::TempDir,
        s: &[Selection],
        f: F,
    ) -> Result<Observation> {
        capture(t.path(), s, Duration::from_secs(5), f)
    }
    #[test]
    fn actual_four_roles_share_native_midpoint_and_count_only_allocated_blocks() {
        let (t, s) = fixture();
        let sparse = &s[0].files[0];
        OpenOptions::new()
            .write(true)
            .open(sparse)
            .unwrap()
            .set_len(16 << 20)
            .unwrap();
        let r = run(&t, &s, || Ok(())).unwrap();
        assert_eq!(r.files.len(), 4);
        assert_eq!(r.current_unique_bytes.len(), 4);
        for role in &s {
            assert_eq!(
                r.current_unique_bytes[&role.epoch],
                fs::metadata(&role.files[0]).unwrap().blocks() * 512
            );
        }
        assert!(r.current_unique_bytes[&166] < 16 << 20);
        assert_eq!(
            r.conservative_available_bytes,
            r.before
                .available_bytes
                .min(r.midpoint.available_bytes)
                .min(r.after.available_bytes)
        );
    }
    #[test]
    fn changed_file_diagnostic_identifies_exact_role_path_and_facts() {
        let (t, s) = fixture();
        let path = s[0].files[0].clone();
        let result = run(&t, &s, || {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(1)?;
            file.sync_all()?;
            Ok(())
        });
        let error = match result {
            Ok(_) => panic!("mutated file accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("file allocation/path changed across midpoint"));
        assert!(error.contains(&format!("epoch={}", s[0].epoch)));
        assert!(error.contains(path.to_str().unwrap()));
        for field in ["before=", "held=", "reopened="] {
            assert!(error.contains(field), "{error}");
        }
    }

    #[test]
    fn truncation_growth_same_length_write_and_hole_punch_reject() {
        for operation in 0..4 {
            let (t, s) = fixture();
            let path = s[0].files[0].clone();
            if operation == 2 {
                // Establish a distinct baseline without relying on filesystem clock granularity.
                let f = OpenOptions::new().write(true).open(&path).unwrap();
                let historical = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
                f.set_times(fs::FileTimes::new().set_modified(historical))
                    .unwrap();
                f.sync_all().unwrap();
                assert_eq!(f.metadata().unwrap().mtime(), 1_000_000_000);
            }
            let before_identity = identity(&fs::metadata(&path).unwrap());
            assert!(
                run(&t, &s, || {
                    let mut f = OpenOptions::new().write(true).open(&path)?;
                    match operation {
                        0 => f.set_len(1)?,
                        1 => f.set_len(32768)?,
                        2 => f.write_all(b"changed")?,
                        _ => ensure!(
                            unsafe {
                                libc::fallocate(
                                    f.as_raw_fd(),
                                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                                    0,
                                    4096,
                                )
                            } == 0,
                            "native hole punch failed"
                        ),
                    }
                    f.sync_all()?;
                    if operation == 2 {
                        let after = identity(&f.metadata()?);
                        assert_eq!(&before_identity[..8], &after[..8]);
                        assert_ne!(&before_identity[8..10], &after[8..10]);
                    }
                    eprintln!("allocation mutation operation={operation} before={before_identity:?} after={:?}", identity(&f.metadata()?));
                    Ok(())
                })
                .is_err(),
                "mutation operation={operation} unexpectedly accepted"
            );
        }
    }
    #[test]
    fn unlinked_inode_stays_held_and_replacement_never_counts() {
        let (t, s) = fixture();
        let path = s[0].files[0].clone();
        let inode = fs::metadata(&path).unwrap().ino();
        assert!(
            run(&t, &s, || {
                fs::remove_file(&path)?;
                let mut f = File::create(&path)?;
                f.write_all(&[7u8; 16384])?;
                f.sync_all()?;
                ensure!(
                    f.metadata()?.ino() != inode,
                    "held descriptor must prevent reuse"
                );
                Ok(())
            })
            .is_err()
        );
    }
    #[test]
    fn hardlinks_and_repeated_paths_reject() {
        let (t, mut s) = fixture();
        let same = s[0].files[0].clone();
        s[0].files.push(same);
        assert!(run(&t, &s, || Ok(())).is_err());
        s[0].files.pop();
        let linked = s[1].root.join("link");
        fs::hard_link(&s[0].files[0], &linked).unwrap();
        assert!(run(&t, &s, || Ok(())).is_err());
    }
    #[test]
    fn symlink_leaf_and_ancestor_reject_without_following() {
        let (t, mut s) = fixture();
        let original = s[0].files[0].clone();
        let linked = s[0].root.join("symlink");
        symlink(&original, &linked).unwrap();
        s[0].files = vec![linked];
        assert!(run(&t, &s, || Ok(())).is_err());
        let alias = t.path().join("alias");
        symlink(&s[1].root, &alias).unwrap();
        s[0].root = alias.clone();
        s[0].files = vec![alias.join("allocated")];
        assert!(run(&t, &s, || Ok(())).is_err());
    }
    #[test]
    fn directory_replacement_and_permission_change_reject() {
        for change in [false, true] {
            let (t, s) = fixture();
            let root = s[0].root.clone();
            assert!(
                run(&t, &s, || {
                    if change {
                        let mode = fs::metadata(&root)?.permissions().mode() ^ 0o100;
                        fs::set_permissions(&root, fs::Permissions::from_mode(mode))?;
                    } else {
                        fs::rename(&root, t.path().join("old"))?;
                        fs::create_dir(&root)?;
                    }
                    Ok(())
                })
                .is_err()
            );
        }
    }
    #[test]
    fn unrelated_child_creation_does_not_invent_allocation_credit() {
        let (t, s) = fixture();
        let expected = fs::metadata(&s[0].files[0]).unwrap().blocks() * 512;
        let r = run(&t, &s, || {
            fs::write(s[0].root.join("new-child"), [1u8; 8192])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(r.current_unique_bytes[&166], expected);
    }
    #[test]
    fn callback_failure_and_expired_window_are_not_native_evidence() {
        let (t, s) = fixture();
        assert!(run(&t, &s, || anyhow::bail!("changed producer identity")).is_err());
        assert!(capture(t.path(), &s, Duration::ZERO, || Ok(())).is_err());
        assert!(capture(t.path(), &s, Duration::from_nanos(1), || Ok(())).is_err());
    }
    #[test]
    fn foreign_duplicate_empty_and_overlapping_roles_reject() {
        let (t, mut s) = fixture();
        s[0].epoch = 200;
        assert!(run(&t, &s, || Ok(())).is_err());
        s[0].epoch = 167;
        assert!(run(&t, &s, || Ok(())).is_err());
        s[0].epoch = 166;
        s[0].files.clear();
        assert!(run(&t, &s, || Ok(())).is_err());
        s[0].root = t.path().to_owned();
        s[0].files = vec![s[1].files[0].clone()];
        assert!(run(&t, &s, || Ok(())).is_err());
    }
    #[test]
    fn foreign_mount_noncanonical_path_and_outside_file_reject() {
        let (t, mut s) = fixture();
        assert!(capture(Path::new("/proc"), &s, Duration::from_secs(5), || Ok(())).is_err());
        s[0].files = vec![s[1].files[0].clone()];
        assert!(run(&t, &s, || Ok(())).is_err());
        s[0].files = vec![s[0].root.join("./allocated")];
        assert!(run(&t, &s, || Ok(())).is_err());
    }
    #[test]
    fn selection_bound_is_checked_before_opening_files() {
        let (t, mut s) = fixture();
        s[0].files = vec![s[0].files[0].clone(); MAX_FILES + 1];
        assert!(run(&t, &s, || Ok(())).is_err());
    }
    #[test]
    fn handles_remain_live_through_enclosing_decision() {
        let (t, s) = fixture();
        let result = run(&t, &s, || Ok(())).unwrap();
        result.revalidate().unwrap();
        fs::remove_file(&s[0].files[0]).unwrap();
        assert!(result.revalidate().is_err());
    }
    #[test]
    fn baseline_age_rechecks_captured_facts_and_rejects_fresh_files() {
        let (t, s) = fixture();
        let r = run(&t, &s, || Ok(())).unwrap();
        let newest = r
            .files
            .iter()
            .map(|f| f.identity[8].max(f.identity[10]))
            .max()
            .unwrap();
        assert!(r.require_minimum_age(newest, 3600).is_err());
        assert!(r.require_minimum_age(newest + 3599, 3600).is_err());
        r.require_minimum_age(newest + 3600, 3600).unwrap();
        assert!(r.require_minimum_age(newest + 3600, 0).is_err());
        assert!(r.require_minimum_age(newest + 3600, 3601).is_err());
        assert!(r.require_minimum_age(1, 3600).is_err());
    }
    #[test]
    fn old_mtime_cannot_hide_recent_ctime_from_baseline_age() {
        let (t, s) = fixture();
        let f = OpenOptions::new().write(true).open(&s[0].files[0]).unwrap();
        f.set_times(
            fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
        )
        .unwrap();
        f.sync_all().unwrap();
        let r = run(&t, &s, || Ok(())).unwrap();
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(r.files[0].identity[8], 1_000_000_000);
        assert!(r.require_minimum_age(at, 3600).is_err());
    }
}
