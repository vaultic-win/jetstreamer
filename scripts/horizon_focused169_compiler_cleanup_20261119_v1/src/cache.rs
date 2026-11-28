use super::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Identity {
    pub dev: u64,
    pub ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    pub links: u64,
    length: u64,
    blocks: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl Identity {
    pub fn of(m: &fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            links: m.nlink(),
            length: m.len(),
            blocks: m.blocks(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
    fn stable_file(&self, b: &Self) -> bool {
        self.dev == b.dev
            && self.ino == b.ino
            && self.mode == b.mode
            && self.uid == b.uid
            && self.gid == b.gid
            && self.length == b.length
            && self.blocks == b.blocks
            && self.mtime == b.mtime
            && self.mtime_nsec == b.mtime_nsec
    }
    fn stable_dir(&self, b: &Self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
            && self.dev == b.dev
            && self.ino == b.ino
            && self.mode == b.mode
            && self.uid == b.uid
            && self.gid == b.gid
            && self.links == b.links
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Group {
    pub identity: Identity,
    pub paths: Vec<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct Selection {
    pub target: PathBuf,
    pub selected: Vec<Group>,
    pub preserved: BTreeMap<PathBuf, Identity>,
    pub directories: BTreeMap<PathBuf, Identity>,
    pub allocated_bytes: u64,
    pub selected_allocated_bytes: u64,
    pub metadata_sha256: String,
}
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}
fn forbidden(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s.ends_with(".jet")
            || s.ends_with(".sha256")
            || s.starts_with("snapshot-")
            || s.ends_with(".tar.zst")
            || s.ends_with(".tar.bz2")
            || s == "receipts"
            || s == "accounts"
            || s == "ledger"
    })
}
fn retained_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with(".lock") || s.starts_with(".cargo-"))
}
fn magic(path: &Path, expected: &Identity, prefix: &[u8]) -> Result<bool> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        Identity::of(&f.metadata()?) == *expected,
        "compiler file changed before identification"
    );
    let mut bytes = vec![0; prefix.len()];
    let got = f.read(&mut bytes)?;
    ensure!(
        Identity::of(&f.metadata()?) == *expected
            && Identity::of(&fs::symlink_metadata(path)?) == *expected,
        "compiler file changed during identification"
    );
    Ok(got == prefix.len() && bytes == prefix)
}
// Deliberately preserve diagnostics, generated sources, fingerprints, dependency
// manifests and unknown files. Only recognizable native/Rust compiler products
// in Cargo output positions can enter a deletion group.
fn compiler_file(root: &Path, relative: &Path, m: &Identity, build_only: bool) -> Result<bool> {
    if retained_lock(relative) {
        return Ok(false);
    }
    let name = relative
        .file_name()
        .and_then(|s| s.to_str())
        .context("nonUTF8 compiler name")?;
    let first = relative
        .components()
        .next()
        .context("empty compiler path")?
        .as_os_str();
    let in_outputs = build_only || first == "deps" || first == "build" || first == "incremental";
    let ext = relative.extension().and_then(|s| s.to_str());
    if in_outputs && matches!(ext, Some("o" | "so")) {
        return magic(&root.join(relative), m, b"\x7fELF");
    }
    if in_outputs && matches!(ext, Some("a" | "rlib")) {
        return magic(&root.join(relative), m, b"!<arch>\n");
    }
    if in_outputs && ext == Some("rmeta") {
        return magic(&root.join(relative), m, b"rust");
    }
    if in_outputs && name.ends_with(".pre-lto.bc") {
        return magic(&root.join(relative), m, b"BC\xc0\xde");
    }
    let stem_hash = name.rsplit_once('-').is_some_and(|(s, h)| {
        !s.is_empty() && h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit())
    });
    let top_binary = relative.components().count() == 1
        && name.starts_with("jetstreamer-")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b));
    if m.mode & 0o111 != 0
        && (top_binary || (in_outputs && (stem_hash || name == "build-script-build")))
    {
        return magic(&root.join(relative), m, b"\x7fELF");
    }
    Ok(false)
}
pub(super) fn select(root: &Path, uid: u32, build_only: bool) -> Result<Selection> {
    let initial = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root && initial.is_dir(),
        "aliased/non-directory cache root"
    );
    let mut out = Selection {
        target: root.to_path_buf(),
        selected: vec![],
        preserved: BTreeMap::new(),
        directories: BTreeMap::new(),
        allocated_bytes: 0,
        selected_allocated_bytes: 0,
        metadata_sha256: String::new(),
    };
    let mut groups: BTreeMap<(u64, u64), (Identity, Vec<PathBuf>, bool)> = BTreeMap::new();
    let mut all = BTreeMap::new();
    let mut dir_inodes = BTreeSet::new();
    let mut todo = vec![(root.to_path_buf(), 0)];
    let start = std::time::Instant::now();
    while let Some((path, depth)) = todo.pop() {
        ensure!(
            all.len() < 250_000 && depth < 128 && start.elapsed().as_secs() < 180,
            "compiler census exceeded bound"
        );
        let md = fs::symlink_metadata(&path)?;
        let symlink = md.file_type().is_symlink();
        let id = Identity::of(&md);
        let relative = path.strip_prefix(root)?.to_path_buf();
        ensure!(
            md.dev() == initial.dev()
                && md.uid() == uid
                && md.gid() == uid
                && (symlink || md.mode() & 0o7002 == 0)
                && (md.is_dir() || md.is_file() || symlink),
            "foreign/special/mutable cache entry: {}",
            path.display()
        );
        ensure!(
            !forbidden(&relative),
            "archive/replay/evidence data in selected compiler tree"
        );
        ensure!(
            all.insert(relative.clone(), id.clone()).is_none(),
            "repeated cache path"
        );
        if md.is_dir() {
            ensure!(
                dir_inodes.insert((md.dev(), md.ino())),
                "directory inode alias"
            );
            out.allocated_bytes = out
                .allocated_bytes
                .checked_add(md.blocks().checked_mul(512).context("blocks")?)
                .context("allocation overflow")?;
            out.directories.insert(relative, id);
            for e in fs::read_dir(&path)? {
                todo.push((e?.path(), depth + 1));
            }
        } else if symlink {
            // Retain libtool aliases without following or selecting their target.
            // Replacement remains visible in the complete inode census.
            ensure!(
                md.nlink() == 1,
                "shared symlink inode requires separate qualification"
            );
            out.allocated_bytes = out
                .allocated_bytes
                .checked_add(md.blocks().checked_mul(512).context("symlink blocks")?)
                .context("allocation overflow")?;
            out.preserved.insert(relative, id);
        } else {
            let eligible = compiler_file(root, &relative, &id, build_only)?;
            let entry = groups
                .entry((md.dev(), md.ino()))
                .or_insert((id.clone(), vec![], true));
            ensure!(entry.0 == id, "hardlink identity changed during census");
            entry.1.push(relative);
            entry.2 &= eligible;
        }
    }
    for (_, (id, mut paths, eligible)) in groups {
        paths.sort();
        ensure!(id.links >= paths.len() as u64, "hardlink count drift");
        let bytes = id
            .blocks
            .checked_mul(512)
            .context("group blocks overflow")?;
        out.allocated_bytes = out
            .allocated_bytes
            .checked_add(bytes)
            .context("tree bytes overflow")?;
        if eligible && id.links == paths.len() as u64 {
            out.selected_allocated_bytes = out
                .selected_allocated_bytes
                .checked_add(bytes)
                .context("selection bytes overflow")?;
            out.selected.push(Group {
                identity: id,
                paths,
            });
        } else {
            for p in paths {
                out.preserved.insert(p, id.clone());
            }
        }
    }
    ensure!(
        Identity::of(&fs::symlink_metadata(root)?) == Identity::of(&initial),
        "cache root changed during census"
    );
    out.metadata_sha256 = sha(&serde_json::to_vec(&all)?);
    Ok(out)
}
fn open_root(before: &Selection) -> Result<File> {
    ensure!(
        before.target.canonicalize()? == before.target,
        "target ancestor alias"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(&before.target)?;
    ensure!(
        before.directories[Path::new("")].stable_dir(&Identity::of(&f.metadata()?)),
        "target root replaced"
    );
    Ok(f)
}
fn open_at(parent: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    ensure!(
        fd >= 0,
        "openat failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn parent_fd(before: &Selection, relative: &Path) -> Result<File> {
    ensure!(safe_relative(relative), "invalid relative candidate");
    let mut fd = open_root(before)?;
    let mut path = PathBuf::new();
    for part in relative.parent().context("relative parent")?.components() {
        path.push(part.as_os_str());
        fd = open_at(&fd, part.as_os_str(), libc::O_RDONLY | libc::O_DIRECTORY)?;
        let id = Identity::of(&fd.metadata()?);
        ensure!(
            before
                .directories
                .get(&path)
                .is_some_and(|v| v.stable_dir(&id)),
            "candidate parent replaced"
        );
    }
    Ok(fd)
}
pub(super) fn unlink_group(before: &Selection, group: &Group) -> Result<()> {
    ensure!(
        !group.paths.is_empty() && group.identity.links == group.paths.len() as u64,
        "group not wholly contained"
    );
    let first = &group.paths[0];
    let parent = parent_fd(before, first)?;
    let held = open_at(&parent, first.file_name().context("leaf")?, libc::O_RDONLY)?;
    let mut expected = Identity::of(&held.metadata()?);
    ensure!(
        expected == group.identity,
        "group inode changed before unlink"
    );
    for path in &group.paths {
        let directory = parent_fd(before, path)?;
        let leaf = path.file_name().context("group leaf")?;
        let current = open_at(&directory, leaf, libc::O_RDONLY)?;
        ensure!(
            Identity::of(&current.metadata()?) == expected
                && Identity::of(&held.metadata()?) == expected,
            "group metadata/link count changed before unlink"
        );
        // Re-open immediately before unlinkat: both checks and unlink use the
        // same directory descriptor. Directory substitutions cannot redirect it.
        let last = open_at(&directory, leaf, libc::O_RDONLY)?;
        ensure!(
            Identity::of(&last.metadata()?) == expected,
            "group path swapped before unlink"
        );
        let name = std::ffi::CString::new(leaf.as_bytes())?;
        ensure!(
            unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "unlinkat failed: {}",
            std::io::Error::last_os_error()
        );
        directory.sync_all()?;
        let after = Identity::of(&held.metadata()?);
        ensure!(
            expected.stable_file(&after) && after.links.checked_add(1) == Some(expected.links),
            "unexpected inode mutation during group unlink"
        );
        // Only our witnessed link removal permits the new ctime/nlink pair.
        expected = after;
    }
    ensure!(expected.links == 0, "group gained an external link");
    Ok(())
}
pub(super) fn verify_after(before: &Selection, uid: u32, build_only: bool) -> Result<Selection> {
    let after = select(&before.target, uid, build_only)?;
    ensure!(
        after.selected.is_empty()
            && before.preserved == after.preserved
            && before.directories.len() == after.directories.len()
            && before
                .directories
                .iter()
                .all(|(p, id)| after.directories.get(p).is_some_and(|m| id.stable_dir(m))),
        "preserved files/directories changed or new files appeared"
    );
    for group in &before.selected {
        for path in &group.paths {
            match fs::symlink_metadata(before.target.join(path)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => anyhow::bail!("selected path not absent"),
            }
        }
    }
    Ok(after)
}
pub(super) fn retire(before: &Selection, uid: u32, build_only: bool) -> Result<Selection> {
    ensure!(
        select(&before.target, uid, build_only)? == *before,
        "complete selection drift before execute"
    );
    for group in &before.selected {
        unlink_group(before, group)?;
    }
    verify_after(before, uid, build_only)
}
