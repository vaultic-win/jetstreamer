//! Read-only allocation witness for existing invocation-bound Foundation roots.
use super::*;
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
};

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// Charge small files at their full growth obligation. They contribute little disk credit
// and would otherwise dominate the controller's file and extent accounting.
const MIN_MEASURED_FILE_BYTES: u64 = 16 << 10;
const EXTRACT_226_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-extract-v3";

fn open_beneath(parent: &File, relative: &Path, flags: libc::c_int) -> std::io::Result<File> {
    let path = CString::new(relative.as_os_str().as_encoded_bytes())?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        // RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV.
        resolve: 0x08 | 0x04 | 0x01,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
}

fn open_member(parent: &File, relative: &Path, flags: libc::c_int) -> Result<Option<File>> {
    match open_beneath(parent, relative, flags) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ELOOP | libc::EXDEV | libc::ENOTDIR)
            ) =>
        {
            Ok(None)
        }
        Err(error) => {
            Err(error).with_context(|| format!("open allocation member {}", relative.display()))
        }
    }
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    inode: u64,
    len: u64,
    blocks: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            inode: metadata.ino(),
            len: metadata.len(),
            blocks: metadata.blocks(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn grows_to(&self, next: &Self) -> bool {
        self.inode == next.inode && self.len <= next.len && self.blocks <= next.blocks
    }
}

fn growing_archive(root: &Path, directory: &Path, name: &OsStr) -> bool {
    // The guarded 726c38e5 extraction creates this output once and writes it
    // directly until the final sync and independent reread.
    let layered_prefix = root == Path::new(EXTRACT_226_ROOT)
        && directory == Path::new("./output")
        && name == OsStr::new("epoch-226-prefix.jet");
    layered_prefix
        || (directory.file_name() == Some(OsStr::new("archives"))
            && name
                .to_str()
                .and_then(|name| name.strip_prefix("epoch-"))
                .and_then(|name| name.strip_suffix(".jet"))
                .is_some_and(|epoch| epoch.parse::<u64>().is_ok()))
}

// Every extent was checked for overflow and exclusive allocation at ingestion.
fn common_ranges(a: &[(u64, u64)], mut b: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut a = a.to_vec();
    a.sort_unstable();
    b.sort_unstable();
    let (mut i, mut j) = (0, 0);
    let mut retained = Vec::new();
    while i < a.len() && j < b.len() {
        let (left, right) = (a[i], b[j]);
        let left_end = left.0 + left.1;
        let right_end = right.0 + right.1;
        let start = left.0.max(right.0);
        let end = left_end.min(right_end);
        if start < end {
            retained.push((start, end - start));
        }
        if left_end <= right_end {
            i += 1;
        }
        if right_end <= left_end {
            j += 1;
        }
    }
    retained
}

struct Claim {
    stamp: FileStamp,
    names_end: u32,
    ranges_end: u32,
}

// Keep one parent path and two append-only buffers per directory. Rechecking each
// claimed inode still requires its exact filename and the full measured ranges.
#[derive(Default)]
struct Group {
    parent: PathBuf,
    claims: Vec<Claim>,
    names: Vec<u8>,
    ranges: Vec<(u64, u64)>,
}

struct Tree {
    root: PathBuf,
    dir: File,
    guard_cap: u64,
    groups: Vec<Group>,
}

fn verify_ext4(file: &File) -> Result<()> {
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } == 0,
        "allocation fstatfs failed"
    );
    ensure!(
        info.f_type == libc::EXT4_SUPER_MAGIC && info.f_bsize == 4096,
        "unqualified allocation filesystem"
    );
    Ok(())
}

fn gather(n: &Native, root: &File, root_path: &Path) -> Result<Vec<Group>> {
    let mut pending = vec![PathBuf::from(".")];
    let mut groups = Vec::new();
    while let Some(relative) = pending.pop() {
        let Some(directory) = open_member(root, &relative, libc::O_RDONLY | libc::O_DIRECTORY)?
        else {
            continue;
        };
        let mut group = Group {
            parent: relative,
            ..Group::default()
        };
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            n.check()?;
            let entry = entry?;
            let name = entry.file_name();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(group.parent.join(name));
            } else if kind.is_file() {
                let metadata = match fs::symlink_metadata(entry.path()) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                };
                if metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.len() >= MIN_MEASURED_FILE_BYTES
                    && metadata.blocks() != 0
                {
                    let Some(file) = open_member(
                        &directory,
                        Path::new(&name),
                        libc::O_RDONLY | libc::O_NONBLOCK,
                    )?
                    else {
                        continue;
                    };
                    let before = file.metadata()?;
                    if !before.is_file()
                        || before.nlink() != 1
                        || before.len() < MIN_MEASURED_FILE_BYTES
                    {
                        continue;
                    }
                    let stamp = FileStamp::of(&before);
                    let growing = growing_archive(root_path, &group.parent, &name);
                    let ranges =
                        native266_full::peer228_extents::stable_file_ranges(&file, growing);
                    let after = file.metadata()?;
                    let last = FileStamp::of(&after);
                    if after.nlink() != 1 || (last != stamp && !(growing && stamp.grows_to(&last)))
                    {
                        continue;
                    }
                    let ranges = ranges?;
                    if ranges.is_empty() {
                        continue;
                    }
                    group.ranges.extend(ranges);
                    group.names.extend_from_slice(name.as_bytes());
                    group.claims.push(Claim {
                        stamp,
                        names_end: u32::try_from(group.names.len())?,
                        ranges_end: u32::try_from(group.ranges.len())?,
                    });
                }
            }
        }
        if !group.claims.is_empty() {
            groups.push(group);
        }
    }
    Ok(groups)
}

fn sample(n: &Native, base: &File, guard: &Value, device: u64) -> Result<Tree> {
    let plan = binding(&guard["plan"])?.sealed()?;
    let root = PathBuf::from(text(&plan, "worker_root")?);
    ensure!(
        root.starts_with("/home/ubuntu/.jetstreamer-private") && root.canonicalize()? == root,
        "unexpected Foundation guard root {}",
        root.display()
    );
    let dir = open_beneath(
        base,
        root.strip_prefix("/")?,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    ensure!(
        dir.metadata()?.dev() == device,
        "Foundation root device differs"
    );
    verify_ext4(&dir)?;
    let groups = gather(n, &dir, &root)?;
    Ok(Tree {
        root,
        dir,
        guard_cap: num(guard, "maximum_root_physical_bytes")?,
        groups,
    })
}

pub(super) fn measure(n: &Native, guards: &BTreeMap<u64, Value>, device: u64) -> Result<Value> {
    let base = File::open("/")?;
    ensure!(
        base.metadata()?.dev() == device,
        "Foundation capacity filesystem changed"
    );
    let free_before = live::resources_at(Path::new(FILESYSTEM))?.2;
    let mut trees = BTreeMap::new();
    for (epoch, guard) in guards {
        let tree = sample(n, &base, guard, device)
            .with_context(|| format!("epoch {epoch} allocation scan"))?;
        ensure!(
            trees
                .values()
                .all(|other: &Tree| !tree.root.starts_with(&other.root)
                    && !other.root.starts_with(&tree.root)),
            "Foundation guard roots overlap"
        );
        trees.insert(*epoch, tree);
    }
    let mut extents = Vec::new();
    let mut witnesses = BTreeMap::new();
    for (epoch, tree) in trees {
        let named = open_beneath(
            &base,
            tree.root.strip_prefix("/")?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let pinned = tree.dir.metadata()?;
        let after = named.metadata()?;
        ensure!(
            (pinned.dev(), pinned.ino()) == (after.dev(), after.ino()),
            "Foundation guard root rotated"
        );
        let mut accepted = 0u64;
        let mut files = 0usize;
        let mut manifest = Sha256::new();
        for group in tree.groups {
            let Some(parent) =
                open_member(&tree.dir, &group.parent, libc::O_RDONLY | libc::O_DIRECTORY)?
            else {
                continue;
            };
            let (mut name_start, mut extent_start) = (0, 0);
            for claim in group.claims {
                n.check()?;
                let name = &group.names[name_start..claim.names_end as usize];
                let ranges = &group.ranges[extent_start..claim.ranges_end as usize];
                name_start = claim.names_end as usize;
                extent_start = claim.ranges_end as usize;
                let name = OsStr::from_bytes(name);
                let growing = growing_archive(&tree.root, &group.parent, name);
                let flags = if growing {
                    libc::O_RDONLY | libc::O_NONBLOCK
                } else {
                    libc::O_PATH
                };
                let Some(file) = open_member(&parent, Path::new(name), flags)? else {
                    continue;
                };
                let current = file.metadata()?;
                if !current.is_file() || current.nlink() != 1 {
                    continue;
                }
                let current_stamp = FileStamp::of(&current);
                let remeasured;
                let ranges = if current_stamp == claim.stamp {
                    ranges
                } else if growing && claim.stamp.grows_to(&current_stamp) {
                    remeasured = common_ranges(
                        ranges,
                        native266_full::peer228_extents::stable_file_ranges(&file, true)?,
                    );
                    if remeasured.is_empty() || file.metadata()?.nlink() != 1 {
                        continue;
                    }
                    &remeasured
                } else {
                    continue;
                };
                manifest.update(current.ino().to_le_bytes());
                manifest.update(current.ctime().to_le_bytes());
                manifest.update(current.ctime_nsec().to_le_bytes());
                files += 1;
                for &(start, length) in ranges {
                    extents.push((start, capacity::add(start, length)?));
                    accepted = capacity::add(accepted, length)?;
                    manifest.update(start.to_le_bytes());
                    manifest.update(length.to_le_bytes());
                }
            }
        }
        ensure!(
            accepted <= tree.guard_cap,
            "physical data already exceeds guard cap"
        );
        witnesses.insert(epoch, json!({"root":tree.root,"device":device,"root_inode":pinned.ino(),
            "rechecked_files":files,"stable_physical_data_bytes":accepted,"extent_map_sha256":format!("{:x}",manifest.finalize()),
            "guard_cap_bytes":tree.guard_cap,"remaining_upper_bound_bytes":tree.guard_cap-accepted}));
    }
    extents.sort_unstable();
    ensure!(
        extents.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "overlapping physical data across Foundation guard roots"
    );
    let free_after = live::resources_at(Path::new(FILESYSTEM))?.2;
    Ok(
        json!({"method":"bracketed exclusive physical extents on each checked inode, with a renewed physical intersection for growing archives",
        "minimum_measured_file_bytes":MIN_MEASURED_FILE_BYTES,
        "first_available_bytes":free_before,"last_available_bytes":free_after,
        "conservative_available_bytes":free_before.min(free_after),"roots":witnesses}),
    )
}

#[cfg(test)]
mod tests {
    use super::{EXTRACT_226_ROOT, common_ranges, growing_archive};
    use std::{ffi::OsStr, path::Path};

    #[test]
    fn growing_archive_credits_only_the_physically_retained_range() {
        assert_eq!(
            common_ranges(&[(64, 16), (0, 32)], vec![(32, 16), (56, 16), (8, 8)]),
            vec![(8, 8), (64, 8)]
        );
    }

    #[test]
    fn recognizes_only_the_exact_layered_extraction_prefix() {
        let root = Path::new(EXTRACT_226_ROOT);
        let archive = OsStr::new("epoch-226-prefix.jet");
        assert!(growing_archive(
            root,
            Path::new(".").join("output").as_path(),
            archive
        ));
        assert!(!growing_archive(
            Path::new("/tmp"),
            Path::new("./output"),
            archive
        ));
        assert!(!growing_archive(root, Path::new("./other/output"), archive));
        assert!(!growing_archive(
            root,
            Path::new("./output"),
            OsStr::new("epoch-226-prefix.jet.segment.json")
        ));
        assert!(growing_archive(
            Path::new("/tmp"),
            Path::new("./run/archives"),
            OsStr::new("epoch-260.jet")
        ));
    }
}
