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

fn gather(n: &Native, root: &File) -> Result<Vec<Group>> {
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
                    let ranges = native266_full::peer228_extents::stable_file_ranges(&file);
                    if FileStamp::of(&file.metadata()?) != stamp {
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
    let groups = gather(n, &dir)?;
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
                let Some(file) =
                    open_member(&parent, Path::new(OsStr::from_bytes(name)), libc::O_PATH)?
                else {
                    continue;
                };
                let current = file.metadata()?;
                if !current.is_file()
                    || current.nlink() != 1
                    || FileStamp::of(&current) != claim.stamp
                {
                    continue;
                }
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
        json!({"method":"same exclusive physical data extents in two FIEMAP reads per unchanged regular inode",
        "minimum_measured_file_bytes":MIN_MEASURED_FILE_BYTES,
        "first_available_bytes":free_before,"last_available_bytes":free_after,
        "conservative_available_bytes":free_before.min(free_after),"roots":witnesses}),
    )
}
