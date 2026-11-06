//! Descriptor-anchored ext4 allocation mechanics on one disposable fixture root.
//! This binary cannot authorize replay, admission, reservation credit or freezing.
//! Pinned descriptors DO NOT prevent truncate, hole punch or extent relocation.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("allocation tree fixture is qualified only for Linux x86_64");
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    time::{Duration, Instant},
};

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/allocation-tree-fixture927-v1";
const BLOCK: u64 = 4096;
const CHUNK: usize = 16;
const MAX_FILES: usize = 64;
const MAX_DIRS: usize = 16; // Includes the selected root.
const MAX_DEPTH: usize = 8;
const MAX_NAME: usize = 255;
const MAX_PATH: usize = 1024;
const MAX_ENTRIES: usize = 128;
const MAX_DIRENT_RECORDS: usize = 512; // Includes final inventory validation.
const MAX_FILE_LENGTH: u64 = 64 << 20;
const MAX_TREE_LENGTH: u64 = 128 << 20;
const MAX_EXTENTS: usize = 4096;
const MAX_MAP_CALLS: usize = 1024;
const MAX_SYSCALL_CHECKS: usize = 4096;
const MAX_MILLIS: u64 = 2500;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const EXTENT_LAST: u32 = 0x01;
const EXTENT_UNWRITTEN: u32 = 0x800;
const FIEMAP_IOCTL: libc::c_ulong = 0xc020660b;

// Each is a fixed child of ROOT. There is no user-supplied filesystem path.
#[derive(Clone, Copy, Debug)]
enum Case {
    Stable,
    Symlink,
    Hardlink,
    Fifo,
    BindMount,
    PinMutation,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Symlink => "symlink",
            Self::Hardlink => "hardlink",
            Self::Fifo => "fifo",
            Self::BindMount => "bind-mount",
            Self::PinMutation => "pin-mutation",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "stable" => Self::Stable,
            "symlink" => Self::Symlink,
            "hardlink" => Self::Hardlink,
            "fifo" => Self::Fifo,
            "bind-mount" => Self::BindMount,
            "pin-mutation" => Self::PinMutation,
            _ => bail!("unknown fixed disposable fixture case"),
        })
    }
    fn relative(self) -> Vec<u8> {
        format!("{}/{}", ROOT.trim_start_matches('/'), self.name()).into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Stable {
    device: u64,
    inode: u64,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    rdev: u64,
    length: u64,
    blocks: u64,
    block_size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
impl Stable {
    fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode(),
            nlink: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            rdev: m.rdev(),
            length: m.len(),
            blocks: m.blocks(),
            block_size: m.blksize(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nsec: m.ctime_nsec(),
        }
    }
    fn kind(&self) -> Result<Kind> {
        match self.mode & libc::S_IFMT {
            libc::S_IFREG => Ok(Kind::Regular),
            libc::S_IFDIR => Ok(Kind::Directory),
            _ => bail!("symlink or nonregular fixture entry"),
        }
    }
    fn validate(&self, device: u64) -> Result<Kind> {
        let kind = self.kind()?;
        ensure!(
            self.device == device && self.uid == 0 && self.gid == 0 && self.rdev == 0,
            "foreign filesystem or fixture ownership"
        );
        ensure!(
            self.mode & 0o7777
                == match kind {
                    Kind::Regular => 0o600,
                    Kind::Directory => 0o700,
                },
            "unexpected fixture mode"
        );
        if kind == Kind::Regular {
            ensure!(
                self.nlink == 1 && self.length <= MAX_FILE_LENGTH,
                "hardlink or oversized fixture file"
            );
        }
        Ok(kind)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Kind {
    Regular,
    Directory,
}

struct Budget {
    started: Instant,
    deadline: Instant,
    checks: usize,
    dirent_records: usize,
    map_calls: usize,
}
impl Budget {
    fn new() -> Self {
        let started = Instant::now();
        Self {
            started,
            deadline: started + Duration::from_millis(MAX_MILLIS),
            checks: 0,
            dirent_records: 0,
            map_calls: 0,
        }
    }
    fn check(&mut self) -> Result<()> {
        self.checks = self
            .checks
            .checked_add(1)
            .context("check counter overflow")?;
        ensure!(
            self.checks <= MAX_SYSCALL_CHECKS && Instant::now() < self.deadline,
            "bounded fixture scan expired or exhausted checks"
        );
        Ok(())
    }
    fn map_call(&mut self) -> Result<()> {
        self.check()?;
        self.map_calls += 1;
        ensure!(self.map_calls <= MAX_MAP_CALLS, "FIEMAP call bound");
        Ok(())
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn open_beneath(parent: RawFd, name: &[u8], flags: i32, budget: &mut Budget) -> Result<File> {
    budget.check()?;
    ensure!(
        !name.is_empty() && name.len() <= MAX_PATH && name[0] != b'/',
        "unbounded/absolute relative path"
    );
    // Kernel BENEATH independently rejects dot-dot escape. Reject it lexically as well.
    ensure!(
        name.split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b".."),
        "unsafe path component"
    );
    let name = CString::new(name)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    ensure!(
        fd >= 0,
        "openat2 refused fixture path: {}",
        std::io::Error::last_os_error()
    );
    // No fallback to openat/canonicalize or cross-mount traversal exists.
    Ok(unsafe { File::from_raw_fd(i32::try_from(fd)?) })
}
fn mount_id(fd: RawFd, budget: &mut Budget) -> Result<u64> {
    budget.check()?;
    let mut s: libc::statx = unsafe { std::mem::zeroed() };
    let empty = c"";
    ensure!(
        unsafe {
            libc::statx(
                fd,
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT,
                libc::STATX_MNT_ID,
                &mut s,
            )
        } == 0,
        "statx mount identity unavailable: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        s.stx_mask & libc::STATX_MNT_ID != 0 && s.stx_mnt_id > 0,
        "kernel omitted mount identity"
    );
    Ok(s.stx_mnt_id)
}
fn ext4_capacity(fd: RawFd, budget: &mut Budget) -> Result<u64> {
    budget.check()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(unsafe { libc::fstatfs(fd, &mut s) } == 0, "fstatfs failed");
    ensure!(
        s.f_type == 0xef53 && s.f_bsize == BLOCK as libc::c_long,
        "requires actual ext4 with 4096-byte blocks"
    );
    // The 0xef53 statfs magic is also used by ext2/ext3. Bind the actual
    // filesystem type to this descriptor's mount, rather than assuming ext4.
    let id = mount_id(fd, budget)?;
    let mut device: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstat(fd, &mut device) } == 0,
        "mount device stat failed"
    );
    let mut mounts = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take(1_048_577)
        .read_to_end(&mut mounts)?;
    budget.check()?;
    validate_ext4_mount(
        &mounts,
        id,
        libc::major(device.st_dev),
        libc::minor(device.st_dev),
    )?;
    ensure!(
        mount_id(fd, budget)? == id,
        "mount changed during filesystem check"
    );
    s.f_blocks
        .checked_mul(BLOCK)
        .filter(|n| *n > 0)
        .context("filesystem size overflow/zero")
}

fn validate_ext4_mount(bytes: &[u8], id: u64, major: u32, minor: u32) -> Result<()> {
    ensure!(bytes.len() <= 1_048_576, "mountinfo size bound");
    let text = std::str::from_utf8(bytes)?;
    let device = format!("{major}:{minor}");
    let mut found = false;
    for (index, line) in text.lines().enumerate() {
        ensure!(index < 8192 && line.len() <= 65536, "mountinfo row bound");
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        ensure!(fields.len() >= 10, "malformed mountinfo row");
        let row_id: u64 = fields[0].parse()?;
        if row_id != id {
            continue;
        }
        ensure!(!found, "duplicate mount identity");
        let separator = fields
            .iter()
            .position(|v| *v == "-")
            .context("mountinfo separator")?;
        ensure!(
            separator >= 6 && fields.len() == separator + 4,
            "malformed selected mountinfo row"
        );
        ensure!(
            fields[2] == device && fields[separator + 1] == "ext4",
            "descriptor mount is not actual ext4/device"
        );
        found = true;
    }
    ensure!(found, "descriptor mount omitted from mountinfo");
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    name: Vec<u8>,
    inode: u64,
    dtype: u8,
}
fn parse_dirents(bytes: &[u8]) -> Result<Vec<Entry>> {
    let mut offset = 0usize;
    let mut out = Vec::new();
    while offset < bytes.len() {
        ensure!(bytes.len() - offset >= 20, "truncated linux_dirent64");
        let inode = u64::from_ne_bytes(bytes[offset..offset + 8].try_into()?);
        let length = u16::from_ne_bytes(bytes[offset + 16..offset + 18].try_into()?) as usize;
        ensure!(
            length >= 24 && length % 8 == 0 && length <= bytes.len() - offset,
            "invalid dirent record length"
        );
        let body = &bytes[offset + 19..offset + length];
        let end = body
            .iter()
            .position(|b| *b == 0)
            .context("unterminated dirent name")?;
        let name = &body[..end];
        ensure!(
            !name.is_empty() && name.len() <= MAX_NAME && !name.contains(&b'/'),
            "invalid dirent component"
        );
        if name != b"." && name != b".." {
            ensure!(inode != 0, "zero dirent inode");
            out.push(Entry {
                name: name.to_vec(),
                inode,
                dtype: bytes[offset + 18],
            });
        }
        offset += length;
    }
    Ok(out)
}
fn directory(fd: RawFd, budget: &mut Budget) -> Result<Vec<Entry>> {
    budget.check()?;
    ensure!(
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } == 0,
        "cannot rewind pinned directory"
    );
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut buf = [0u8; 4096];
    loop {
        budget.check()?;
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        ensure!(
            n >= 0,
            "getdents64 failed: {}",
            std::io::Error::last_os_error()
        );
        if n == 0 {
            break;
        }
        let n = usize::try_from(n)?;
        ensure!(n <= buf.len(), "oversized dirent result");
        // Even dot entries consume budget; no attacker-controlled infinite dot stream.
        let mut at = 0;
        while at < n {
            ensure!(n - at >= 20, "truncated dirent budget record");
            let len = u16::from_ne_bytes(buf[at + 16..at + 18].try_into()?) as usize;
            ensure!(
                len >= 24 && len % 8 == 0 && len <= n - at,
                "invalid dirent budget length"
            );
            budget.dirent_records += 1;
            ensure!(
                budget.dirent_records <= MAX_DIRENT_RECORDS,
                "directory record bound"
            );
            at += len;
        }
        for e in parse_dirents(&buf[..n])? {
            ensure!(
                seen.insert(e.name.clone()),
                "duplicate/repeated directory name"
            );
            entries.push(e);
            ensure!(entries.len() <= MAX_ENTRIES, "directory entry bound");
        }
    }
    entries.sort();
    Ok(entries)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct Extent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}
#[repr(C)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [Extent; CHUNK],
}
fn rounded_length(size: u64) -> Result<u64> {
    ensure!(size <= MAX_FILE_LENGTH, "logical file bound");
    Ok(size
        .checked_add(BLOCK - 1)
        .context("rounded length overflow")?
        / BLOCK
        * BLOCK)
}
#[derive(Default)]
struct Physical {
    ranges: BTreeMap<u64, u64>,
    bytes: u64,
    count: usize,
}
impl Physical {
    fn add(&mut self, start: u64, end: u64) -> Result<()> {
        ensure!(start < end, "empty physical interval");
        if let Some((_, previous_end)) = self.ranges.range(..=start).next_back() {
            ensure!(
                *previous_end <= start,
                "globally shared/overlapping physical extents"
            );
        }
        if let Some((next_start, _)) = self.ranges.range(start..).next() {
            ensure!(
                end <= *next_start,
                "globally shared/overlapping physical extents"
            );
        }
        let bytes = self
            .bytes
            .checked_add(end - start)
            .context("global allocation overflow")?;
        ensure!(
            self.count < MAX_EXTENTS && bytes <= MAX_TREE_LENGTH,
            "extent/unique-byte bound"
        );
        self.ranges.insert(start, end);
        self.bytes = bytes;
        self.count += 1;
        Ok(())
    }
}
fn accept_chunk(
    map: &Fiemap,
    start: u64,
    limit: u64,
    capacity: u64,
    global: &mut Physical,
) -> Result<(u64, bool, Vec<Extent>)> {
    ensure!(
        start < limit
            && map.start == start
            && map.length == limit - start
            && map.flags == 0
            && map.count == CHUNK as u32
            && map.reserved == 0
            && map.mapped <= CHUNK as u32,
        "FIEMAP header changed/invalid"
    );
    if map.mapped == 0 {
        return Ok((limit, true, vec![]));
    }
    let mut cursor = start;
    let mut done = false;
    let mut accepted = Vec::new();
    for (i, e) in map.extents[..map.mapped as usize].iter().enumerate() {
        ensure!(
            e.length > 0
                && e.physical > 0
                && e.logical >= cursor
                && e.logical % BLOCK == 0
                && e.physical % BLOCK == 0
                && e.length % BLOCK == 0
                && e.flags & !(EXTENT_LAST | EXTENT_UNWRITTEN) == 0
                && e.reserved64 == [0; 2]
                && e.reserved == [0; 3],
            "unsupported, unaligned or unstable extent"
        );
        let logical_end = e
            .logical
            .checked_add(e.length)
            .context("logical extent overflow")?;
        let physical_end = e
            .physical
            .checked_add(e.length)
            .context("physical extent overflow")?;
        ensure!(
            logical_end <= limit && physical_end <= capacity,
            "extent outside requested file/filesystem"
        );
        if e.flags & EXTENT_LAST != 0 {
            ensure!(
                i + 1 == map.mapped as usize,
                "LAST before end of FIEMAP chunk"
            );
            done = true;
        }
        global.add(e.physical, physical_end)?;
        cursor = logical_end;
        accepted.push(*e);
    }
    ensure!(cursor > start, "FIEMAP cursor made no progress");
    Ok((cursor, done || cursor == limit, accepted))
}
fn map_file(
    fd: RawFd,
    stable: &Stable,
    capacity: u64,
    global: &mut Physical,
    budget: &mut Budget,
) -> Result<Vec<Extent>> {
    let limit = rounded_length(stable.length)?;
    if limit == 0 {
        return Ok(vec![]);
    }
    let mut start = 0;
    let mut extents = Vec::new();
    let initial_bytes = global.bytes;
    while start < limit {
        budget.map_call()?;
        let mut map = Fiemap {
            start,
            length: limit - start,
            flags: 0,
            mapped: 0,
            count: CHUNK as u32,
            reserved: 0,
            extents: [Extent::default(); CHUNK],
        };
        ensure!(
            unsafe { libc::ioctl(fd, FIEMAP_IOCTL, &mut map) } == 0,
            "FIEMAP ioctl failed: {}",
            std::io::Error::last_os_error()
        );
        let (next, done, chunk) = accept_chunk(&map, start, limit, capacity, global)?;
        extents.extend(chunk);
        start = next;
        if done {
            break;
        }
    }
    // st_blocks is a consistency ceiling only. No credit is derived from it.
    ensure!(
        global.bytes - initial_bytes
            <= stable
                .blocks
                .checked_mul(512)
                .context("st_blocks overflow")?,
        "FIEMAP exceeds stat allocation ceiling"
    );
    Ok(extents)
}

struct Node {
    fd: File,
    path: Vec<u8>,
    stable: Stable,
    kind: Kind,
    mount: u64,
    entries: Option<Vec<Entry>>,
}
struct Tree {
    anchor: File,
    nodes: Vec<Node>,
    seen: BTreeSet<(u64, u64)>,
    files: usize,
    dirs: usize,
    entries: usize,
    logical: u64,
    device: u64,
    mount: u64,
    capacity: u64,
}
impl Tree {
    fn root(case: Case, budget: &mut Budget) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Root identity required for private disposable fixture"
        );
        budget.check()?;
        let anchor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/")?;
        // NO_XDEV applies from / through every fixed ancestor, rejecting even a
        // same-device bind mount at the fixture root. No canonicalize fallback.
        let fd = open_beneath(
            anchor.as_raw_fd(),
            &case.relative(),
            libc::O_RDONLY | libc::O_DIRECTORY,
            budget,
        )?;
        let stable = Stable::of(&fd.metadata()?);
        let device = stable.device;
        ensure!(
            stable.validate(device)? == Kind::Directory,
            "fixture root is not a directory"
        );
        let mount = mount_id(fd.as_raw_fd(), budget)?;
        ensure!(
            mount == mount_id(anchor.as_raw_fd(), budget)?,
            "fixture root crosses anchor mount"
        );
        let capacity = ext4_capacity(fd.as_raw_fd(), budget)?;
        let mut seen = BTreeSet::new();
        seen.insert((stable.device, stable.inode));
        Ok(Self {
            anchor,
            nodes: vec![Node {
                fd,
                path: case.relative(),
                stable,
                kind: Kind::Directory,
                mount,
                entries: None,
            }],
            seen,
            files: 0,
            dirs: 1,
            entries: 0,
            logical: 0,
            device,
            mount,
            capacity,
        })
    }
    fn walk(&mut self, index: usize, depth: usize, budget: &mut Budget) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "tree depth bound");
        budget.check()?;
        let parent_fd = self.nodes[index].fd.as_raw_fd();
        let entries = directory(parent_fd, budget)?;
        let parent_path = self.nodes[index].path.clone();
        for entry in &entries {
            budget.check()?;
            self.entries += 1;
            ensure!(self.entries <= MAX_ENTRIES, "total entry bound");
            // O_PATH classifies FIFO/devices/symlinks without opening their data.
            let probe = open_beneath(parent_fd, &entry.name, libc::O_PATH, budget)?;
            let before = Stable::of(&probe.metadata()?);
            let kind = before.validate(self.device)?;
            ensure!(
                before.inode == entry.inode,
                "dirent/descriptor inode changed"
            );
            let expected_dtype = match kind {
                Kind::Regular => libc::DT_REG,
                Kind::Directory => libc::DT_DIR,
            };
            ensure!(
                entry.dtype == libc::DT_UNKNOWN || entry.dtype == expected_dtype,
                "dirent type disagrees with inode"
            );
            ensure!(
                self.seen.insert((before.device, before.inode)),
                "duplicate inode/directory alias"
            );
            let flags = libc::O_RDONLY
                | libc::O_NONBLOCK
                | if kind == Kind::Directory {
                    libc::O_DIRECTORY
                } else {
                    0
                };
            let fd = open_beneath(parent_fd, &entry.name, flags, budget)?;
            ensure!(
                Stable::of(&fd.metadata()?) == before,
                "entry replaced between classification and readable open"
            );
            let mount = mount_id(fd.as_raw_fd(), budget)?;
            ensure!(mount == self.mount, "child mount changed");
            drop(probe);
            match kind {
                Kind::Regular => {
                    self.files += 1;
                    self.logical = self
                        .logical
                        .checked_add(before.length)
                        .context("tree logical overflow")?;
                    ensure!(
                        self.files <= MAX_FILES && self.logical <= MAX_TREE_LENGTH,
                        "file/logical byte bound"
                    );
                }
                Kind::Directory => {
                    self.dirs += 1;
                    ensure!(self.dirs <= MAX_DIRS, "directory/descriptor bound");
                }
            }
            let mut path = parent_path.clone();
            path.push(b'/');
            path.extend_from_slice(&entry.name);
            ensure!(path.len() <= MAX_PATH, "relative path bound");
            let child = self.nodes.len();
            self.nodes.push(Node {
                fd,
                path,
                stable: before,
                kind,
                mount,
                entries: None,
            });
            if kind == Kind::Directory {
                self.walk(child, depth + 1, budget)?;
            }
        }
        ensure!(
            Stable::of(&self.nodes[index].fd.metadata()?) == self.nodes[index].stable,
            "directory metadata changed during traversal"
        );
        self.nodes[index].entries = Some(entries);
        Ok(())
    }
    fn validate_all(&self, budget: &mut Budget) -> Result<()> {
        for node in &self.nodes {
            budget.check()?;
            ensure!(
                Stable::of(&node.fd.metadata()?) == node.stable
                    && mount_id(node.fd.as_raw_fd(), budget)? == node.mount,
                "pinned inode metadata/mount changed"
            );
            // Resolve every name again from the pinned / descriptor. Holding the
            // old fd alone would not detect replacement of its namespace path.
            let reopened = open_beneath(self.anchor.as_raw_fd(), &node.path, libc::O_PATH, budget)?;
            ensure!(
                Stable::of(&reopened.metadata()?) == node.stable
                    && mount_id(reopened.as_raw_fd(), budget)? == node.mount,
                "anchored namespace replaced or aliased"
            );
            if let Some(expected) = &node.entries {
                ensure!(
                    &directory(node.fd.as_raw_fd(), budget)? == expected,
                    "directory membership changed"
                );
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct FileObservation {
    relative_path_hex: String,
    identity: Stable,
    extents: Vec<Extent>,
}
#[derive(Serialize)]
struct Observation {
    schema: &'static str,
    fixture_only: bool,
    fixture_root: &'static str,
    case: &'static str,
    root_identity: Stable,
    mount_id: u64,
    files: usize,
    directories: usize,
    extent_count: usize,
    unique_physical_extent_bytes_observed: u64,
    file_observations: Vec<FileObservation>,
    fiemap_calls: usize,
    elapsed_millis: u128,
    quiescence_proven: bool,
    fd_pinning_prevents_truncate: bool,
    capacity_credit_bytes: u64,
    admission_authorized: bool,
    live_replay_authorized: bool,
}
fn scan(case: Case) -> Result<Observation> {
    let mut budget = Budget::new();
    let mut tree = Tree::root(case, &mut budget)?;
    tree.walk(0, 0, &mut budget)?;
    // All discovered file and directory descriptors remain pinned together
    // through mapping and every final namespace/metadata/membership check.
    let mut physical = Physical::default();
    let mut files = Vec::new();
    for node in &tree.nodes {
        if node.kind == Kind::Regular {
            let extents = map_file(
                node.fd.as_raw_fd(),
                &node.stable,
                tree.capacity,
                &mut physical,
                &mut budget,
            )?;
            ensure!(
                Stable::of(&node.fd.metadata()?) == node.stable,
                "file changed while mapping extents"
            );
            files.push(FileObservation {
                relative_path_hex: node.path.iter().map(|b| format!("{b:02x}")).collect(),
                identity: node.stable.clone(),
                extents,
            });
        }
    }
    tree.validate_all(&mut budget)?;
    budget.check()?;
    Ok(Observation {
        schema: "horizon-allocation-tree-fixture-observation-v1",
        fixture_only: true,
        fixture_root: ROOT,
        case: case.name(),
        root_identity: tree.nodes[0].stable.clone(),
        mount_id: tree.mount,
        files: tree.files,
        directories: tree.dirs,
        extent_count: physical.count,
        unique_physical_extent_bytes_observed: physical.bytes,
        file_observations: files,
        fiemap_calls: budget.map_calls,
        elapsed_millis: budget.started.elapsed().as_millis(),
        quiescence_proven: false,
        fd_pinning_prevents_truncate: false,
        capacity_credit_bytes: 0,
        admission_authorized: false,
        live_replay_authorized: false,
    })
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3 && args[1] == "--fixture-case",
        "usage: jetstreamer-allocation-tree-fixture --fixture-case <fixed-case-name>"
    );
    let case = Case::parse(&args[2])?;
    eprintln!(
        "fixture-only allocation scan starting; case={}; hard syscall-loop deadline={}ms; no quiescence or capacity authority",
        case.name(),
        MAX_MILLIS
    );
    let observed = scan(case)?;
    println!("{}", serde_json::to_string(&observed)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("allocation_tree_fixture/tests.rs");
}
