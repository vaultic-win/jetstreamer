use super::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct MemberIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    length: u64,
    blocks: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl MemberIdentity {
    fn from_metadata(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
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
    fn same_directory(&self, other: &Self) -> bool {
        // Unlink changes directory size/allocation and timestamps, but no directory
        // is removed, replaced or chmod/chowned by this partial cleanup.
        self.mode & libc::S_IFMT == libc::S_IFDIR
            && self.device == other.device
            && self.inode == other.inode
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.links == other.links
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct SingleLinkSelection {
    pub cache: Value,
    pub selected_files: BTreeMap<PathBuf, MemberIdentity>,
    pub preserved_shared_files: BTreeMap<PathBuf, MemberIdentity>,
    pub directories: BTreeMap<PathBuf, MemberIdentity>,
    pub selected_allocated_bytes: u64,
}

struct Census {
    summary: Value,
    members: BTreeMap<PathBuf, MemberIdentity>,
}

pub(super) fn pre_lto_bitcode(path: &Path, expected: &fs::Metadata) -> Result<()> {
    ensure!(
        expected.len() >= 4 && expected.mode() & 0o111 == 0,
        "LLVM bitcode member is truncated or executable"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        evidence::identity(expected) == evidence::identity(&file.metadata()?),
        "LLVM bitcode member changed before read"
    );
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    ensure!(magic == *b"BC\xc0\xde", "invalid raw LLVM bitcode magic");
    ensure!(
        evidence::identity(expected) == evidence::identity(&file.metadata()?)
            && evidence::identity(expected) == evidence::identity(&fs::symlink_metadata(path)?),
        "LLVM bitcode member changed during read"
    );
    Ok(())
}

fn incremental_member(path: &Path, m: &fs::Metadata) -> Result<()> {
    ensure!(
        !m.file_type().is_symlink(),
        "incremental cache contains symlink"
    );
    if m.is_dir() {
        return Ok(());
    }
    ensure!(m.is_file(), "incremental cache contains special entry");
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("incremental member name")?;
    let lock = name.strip_suffix(".lock").is_some_and(|s| {
        s.starts_with("s-") && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if lock {
        // rustc may create executable-mode locks; only empty lock files qualify.
        ensure!(m.len() == 0, "incremental lock carries retained bytes");
        return Ok(());
    }
    let object = name
        .strip_suffix(".o")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()));
    let bitcode = name
        .strip_suffix(".pre-lto.bc")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()));
    if bitcode {
        pre_lto_bitcode(path, m)?;
    }
    ensure!(
        m.mode() & 0o111 == 0
            && (object
                || bitcode
                || matches!(
                    name,
                    "dep-graph.bin"
                        | "query-cache.bin"
                        | "work-products.bin"
                        | "metadata.rmeta"
                        | "thin-lto-past-keys.bin"
                )),
        "incremental cache contains executable, failed-test artifact or unknown member: {}",
        path.display()
    );
    Ok(())
}
pub(super) fn reject_incremental_mounts(bytes: &[u8], target: &Path) -> Result<()> {
    ensure!(bytes.len() <= 4 << 20, "mount census exceeded bound");
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let fields: Vec<_> = line
            .split(|b| *b == b' ')
            .filter(|s| !s.is_empty())
            .collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&b"-".as_slice()),
            "invalid mount census row"
        );
        let raw = fields[4];
        let mut decoded = Vec::new();
        let mut at = 0;
        while at < raw.len() {
            if raw[at] == b'\\' {
                ensure!(
                    at + 3 < raw.len()
                        && raw[at + 1..=at + 3]
                            .iter()
                            .all(|b| (b'0'..=b'7').contains(b)),
                    "invalid escaped mount path"
                );
                let value = (raw[at + 1] - b'0') as u16 * 64
                    + (raw[at + 2] - b'0') as u16 * 8
                    + (raw[at + 3] - b'0') as u16;
                ensure!(value > 0 && value <= 255, "invalid mount path byte");
                decoded.push(value as u8);
                at += 4;
            } else {
                decoded.push(raw[at]);
                at += 1;
            }
        }
        let mounted = Path::new(std::ffi::OsStr::from_bytes(&decoded));
        ensure!(mounted.is_absolute(), "nonabsolute mount path");
        ensure!(
            mounted != target && !mounted.starts_with(target),
            "selected incremental cache contains a mount/bind alias"
        );
    }
    Ok(())
}
pub(super) fn incremental_mounts(target: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    reject_incremental_mounts(&bytes, target)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
// Retain the strict API and its external-hardlink rejection for existing callers/tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn cache_tree_with_policy(
    target: &Path,
    expected_uid: u32,
    incremental: bool,
) -> Result<Value> {
    Ok(cache_census(target, expected_uid, incremental, true)?.summary)
}

fn cache_census(
    target: &Path,
    expected_uid: u32,
    incremental: bool,
    reject_external_links: bool,
) -> Result<Census> {
    let root = fs::symlink_metadata(target)?;
    ensure!(
        target.canonicalize()? == target && root.is_dir() && root.uid() == expected_uid,
        "unsafe dev-cache identity"
    );
    let mut queue = vec![(target.to_path_buf(), 0u32)];
    let mut entries = 0u64;
    let mut physical = 0u64;
    let mut regular = 0u64;
    let mut links = 0u64;
    let mut regular_inodes: BTreeMap<(u64, u64), (u64, u64)> = BTreeMap::new();
    let mut directory_inodes = BTreeSet::new();
    let mut member_identities = BTreeMap::new();
    let start = std::time::Instant::now();
    while let Some((path, depth)) = queue.pop() {
        entries += 1;
        ensure!(
            !incremental || start.elapsed().as_secs() < 120,
            "incremental metadata census runtime bound"
        );
        ensure!(
            entries <= 1_000_000 && depth <= 128,
            "cache census exceeded bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == root.dev() && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
            "foreign mount or special cache entry"
        );
        let first_inode = if incremental {
            incremental_member(&path, &m)?;
            ensure!(
                m.uid() == expected_uid && m.gid() == expected_uid && m.mode() & 0o7002 == 0,
                "incremental member owner/mode changed"
            );
            if m.is_dir() {
                ensure!(
                    directory_inodes.insert((m.dev(), m.ino())),
                    "incremental directory inode alias"
                );
            }
            member_identities.insert(
                path.strip_prefix(target)?.to_path_buf(),
                MemberIdentity::from_metadata(&m),
            );
            if m.is_file() {
                let count = regular_inodes
                    .entry((m.dev(), m.ino()))
                    .or_insert((0, m.nlink()));
                ensure!(count.1 == m.nlink(), "incremental hardlink count changed");
                count.0 = count
                    .0
                    .checked_add(1)
                    .context("incremental link count overflow")?;
                count.0 == 1
            } else {
                true
            }
        } else {
            true
        };
        if first_inode {
            physical = physical
                .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
                .context("tree overflow")?;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("nonUTF8 cache member")?;
        ensure!(
            !name.ends_with(".jet")
                && !name.ends_with(".sha256")
                && !name.starts_with("snapshot-")
                && !name.ends_with(".tar.zst")
                && !name.ends_with(".tar.bz2"),
            "archive/snapshot/sidecar found in cache"
        );
        if m.is_dir() {
            for e in fs::read_dir(&path)? {
                queue.push((e?.path(), depth + 1));
            }
        } else if m.is_file() {
            regular += 1;
        } else {
            links += 1;
        }
    }
    if incremental && reject_external_links {
        ensure!(
            regular_inodes.values().all(|(seen, links)| seen == links),
            "incremental cache has a hardlink outside its selected tree; preserve retained artifact"
        );
    }
    let after = fs::symlink_metadata(target)?;
    ensure!(
        root.dev() == after.dev() && root.ino() == after.ino(),
        "cache root changed"
    );
    Ok(Census {
        summary: json!({"path":target,"device":root.dev(),"inode":root.ino(),"uid":root.uid(),"mode":format!("{:04o}",root.mode()&0o7777),
        "physical_bytes":physical,"regular_files":regular,"symlinks_not_followed":links,"entries":entries,
        "unique_regular_inodes":if incremental {Some(regular_inodes.len())}else{None},
        "physical_bytes_deduplicated":incremental,
        "external_hardlinks_rejected":incremental && reject_external_links,
        "home_space_credit_bytes":0,
        "metadata_identity_sha256":if incremental {Some(format!("{:x}",Sha256::digest(serde_json::to_vec(&member_identities)?)))}else{None}}),
        members: member_identities,
    })
}

/// Explicit partial policy: validate every member, but select only single-link
/// regular compiler-cache files. Shared files and every directory stay in place.
pub(super) fn select_single_link_files(
    target: &Path,
    expected_uid: u32,
) -> Result<SingleLinkSelection> {
    let census = cache_census(target, expected_uid, true, false)?;
    let mut selection = SingleLinkSelection {
        cache: census.summary,
        selected_files: BTreeMap::new(),
        preserved_shared_files: BTreeMap::new(),
        directories: BTreeMap::new(),
        selected_allocated_bytes: 0,
    };
    for (path, member) in census.members {
        if member.mode & libc::S_IFMT == libc::S_IFDIR {
            selection.directories.insert(path, member);
        } else if member.links == 1 {
            selection.selected_allocated_bytes = selection
                .selected_allocated_bytes
                .checked_add(
                    member
                        .blocks
                        .checked_mul(512)
                        .context("selected block overflow")?,
                )
                .context("selected allocation overflow")?;
            selection.selected_files.insert(path, member);
        } else {
            ensure!(member.links > 1, "invalid shared link count");
            selection.preserved_shared_files.insert(path, member);
        }
    }
    Ok(selection)
}

pub(super) fn unlink_selected_file(
    target: &Path,
    relative: &Path,
    expected: &MemberIdentity,
    expected_parent: &MemberIdentity,
) -> Result<()> {
    ensure!(
        !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            && expected.mode & libc::S_IFMT == libc::S_IFREG
            && expected.links == 1,
        "invalid partial cleanup candidate"
    );
    let path = target.join(relative);
    let parent = path.parent().context("candidate parent")?;
    ensure!(
        parent.canonicalize()? == parent,
        "candidate directory alias"
    );
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(parent)?;
    ensure!(
        expected_parent.same_directory(&MemberIdentity::from_metadata(&directory.metadata()?))
            && expected_parent.same_directory(&MemberIdentity::from_metadata(
                &fs::symlink_metadata(parent)?
            )),
        "candidate parent changed"
    );
    let name = std::ffi::CString::new(relative.file_name().context("candidate name")?.as_bytes())?;
    let mut raw = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Bind the last check and unlink to the same opened parent directory. No
    // symlink is followed and directories are never passed to unlinkat.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let raw = unsafe { raw.assume_init() };
    let current = MemberIdentity {
        device: raw.st_dev,
        inode: raw.st_ino,
        mode: raw.st_mode,
        uid: raw.st_uid,
        gid: raw.st_gid,
        links: raw.st_nlink,
        length: raw.st_size.try_into()?,
        blocks: raw.st_blocks.try_into()?,
        mtime: raw.st_mtime,
        mtime_nsec: raw.st_mtime_nsec,
        ctime: raw.st_ctime,
        ctime_nsec: raw.st_ctime_nsec,
    };
    ensure!(
        current == *expected && current.links == 1,
        "candidate identity or link count changed before unlink"
    );
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}

pub(super) fn verify_partial_cleanup(
    target: &Path,
    expected_uid: u32,
    before: &SingleLinkSelection,
) -> Result<SingleLinkSelection> {
    let after = select_single_link_files(target, expected_uid)?;
    ensure!(
        after.selected_files.is_empty()
            && after.preserved_shared_files == before.preserved_shared_files
            && after.directories.len() == before.directories.len()
            && before.directories.iter().all(|(path, expected)| after
                .directories
                .get(path)
                .is_some_and(|m| expected.same_directory(m))),
        "partial cleanup changed preserved files/directories or left/newly selected files"
    );
    for relative in before.selected_files.keys() {
        match fs::symlink_metadata(target.join(relative)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("selected path is not absent after partial cleanup"),
        }
    }
    Ok(after)
}

pub(super) fn retire_single_link_files(
    target: &Path,
    expected_uid: u32,
    selection: &SingleLinkSelection,
) -> Result<SingleLinkSelection> {
    ensure!(
        select_single_link_files(target, expected_uid)? == *selection,
        "complete partial cleanup selection changed before unlink"
    );
    for (relative, expected) in &selection.selected_files {
        let parent = relative.parent().context("candidate relative parent")?;
        let expected_parent = selection
            .directories
            .get(parent)
            .context("unbound candidate parent")?;
        unlink_selected_file(target, relative, expected, expected_parent)?;
    }
    verify_partial_cleanup(target, expected_uid, selection)
}
