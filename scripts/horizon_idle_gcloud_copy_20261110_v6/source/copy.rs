//! Descriptor-relative, bounded coherent copies. No network or config installation.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};

const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 64 << 20;
const MAX_FILE: u64 = 32 << 20;
const MAX_DEPTH: usize = 24;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}
impl Directory {
    pub fn from(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
        }
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        bytes: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Logical {
    directory: bool,
    mode: u32,
    bytes: u64,
    sha256: String,
    mtime: i64,
    mtime_ns: i64,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Snapshot {
    identities: BTreeMap<String, Identity>,
    logical: BTreeMap<String, Logical>,
    pub bytes: u64,
}
impl Snapshot {
    pub fn count(&self) -> usize {
        self.logical.len()
    }
    pub fn logical_digest(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(&self.logical)?))
    }
    pub fn source_digest(&self) -> Result<String> {
        Ok(hash(&serde_json::to_vec(self)?))
    }
    pub fn logical_equals(&self, other: &Self) -> bool {
        self.logical == other.logical && self.bytes == other.bytes
    }
}
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn name(s: &str) -> Result<CString> {
    ensure!(
        !s.is_empty() && s != "." && s != ".." && !s.contains('/'),
        "unsafe configuration leaf"
    );
    Ok(CString::new(s)?)
}
fn child(parent: &File, leaf: &str, flags: i32, mode: u32) -> Result<File> {
    let leaf = name(leaf)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("configuration child open failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub fn open_directory(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute(),
        "absolute configuration directory required"
    );
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(s) => {
                directory = child(
                    &directory,
                    s.to_str().context("non-UTF8 directory")?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?
            }
            _ => anyhow::bail!("noncanonical directory component"),
        }
    }
    ensure!(
        path.canonicalize()? == path,
        "configuration directory alias"
    );
    Ok(directory)
}
fn names(directory: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let leaf = item?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 configuration leaf"))?;
        name(&leaf)?;
        names.push(leaf);
        ensure!(
            names.len() <= MAX_ENTRIES,
            "configuration entry limit exceeded"
        );
    }
    names.sort();
    Ok(names)
}
fn metadata(parent: &File, leaf: &str) -> Result<fs::Metadata> {
    name(leaf)?;
    Ok(fs::symlink_metadata(format!(
        "/proc/self/fd/{}/{}",
        parent.as_raw_fd(),
        leaf
    ))?)
}
fn safe(
    m: &fs::Metadata,
    device: u64,
    uid: u32,
    sole_source_gid: Option<u32>,
    relative: &str,
) -> Result<()> {
    // The reviewed group has precisely one member. SDK configuration files are
    // normally 0664 and directories 0775; capture those exact source modes but
    // publish private directories and remove group-write from copied files.
    let private = m.mode() & 0o7022 == 0;
    let sdk_source_member = sole_source_gid == Some(m.gid())
        && ((m.is_dir() && m.mode() & 0o7777 == 0o775)
            || (m.is_file() && m.mode() & 0o7777 == 0o664));
    // Some read-only SDK log files were created by prior Root probes. They are
    // data, never executable/configuration authority. Confine this owner
    // exception to regular 0644 logs, and never apply it to target readback.
    let root_sdk_log = sole_source_gid.is_some()
        && uid == 1001
        && relative.starts_with("logs/")
        && m.is_file()
        && m.uid() == 0
        && m.gid() == 0
        && m.mode() & 0o7777 == 0o644;
    ensure!(
        m.dev() == device
            && ((m.uid() == uid && (private || sdk_source_member)) || root_sdk_log)
            && (m.is_dir() || m.is_file())
            && (!m.is_file() || m.nlink() == 1),
        "foreign, writable-peer, linked or special configuration member"
    );
    Ok(())
}
fn snapshot_at(
    dir: &File,
    prefix: &str,
    device: u64,
    uid: u32,
    sole_source_gid: Option<u32>,
    depth: usize,
    out: &mut Snapshot,
) -> Result<()> {
    ensure!(
        depth <= MAX_DEPTH && out.logical.len() < MAX_ENTRIES,
        "configuration bounds exceeded"
    );
    let before = dir.metadata()?;
    safe(&before, device, uid, sole_source_gid, prefix)?;
    out.identities.insert(prefix.into(), identity(&before));
    out.logical.insert(
        prefix.into(),
        Logical {
            directory: true,
            mode: 0o700,
            bytes: 0,
            sha256: String::new(),
            mtime: before.mtime(),
            mtime_ns: before.mtime_nsec(),
        },
    );
    let children = names(dir)?;
    for leaf in &children {
        ensure!(
            out.logical.len() < MAX_ENTRIES,
            "configuration entry limit exceeded"
        );
        let path = if prefix.is_empty() {
            leaf.clone()
        } else {
            format!("{prefix}/{leaf}")
        };
        let m = metadata(dir, leaf)?;
        safe(&m, device, uid, sole_source_gid, &path)?;
        if m.is_dir() {
            let opened = child(dir, leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            ensure!(
                identity(&m) == identity(&opened.metadata()?),
                "configuration directory changed"
            );
            snapshot_at(&opened, &path, device, uid, sole_source_gid, depth + 1, out)?;
            ensure!(
                identity(&m) == identity(&metadata(dir, leaf)?),
                "configuration directory replaced"
            );
        } else {
            ensure!(m.len() <= MAX_FILE, "configuration file exceeds size bound");
            out.bytes = out
                .bytes
                .checked_add(m.len())
                .context("configuration size overflow")?;
            ensure!(
                out.bytes <= MAX_BYTES,
                "configuration total-byte limit exceeded"
            );
            let mut file = child(dir, leaf, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
            ensure!(
                identity(&m) == identity(&file.metadata()?),
                "configuration file replaced"
            );
            let mut h = Sha256::new();
            let mut bytes = 0u64;
            let mut buffer = [0u8; 64 << 10];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                bytes += read as u64;
                ensure!(bytes <= m.len(), "configuration file grew");
                h.update(&buffer[..read]);
            }
            ensure!(
                bytes == m.len()
                    && identity(&m) == identity(&file.metadata()?)
                    && identity(&m) == identity(&metadata(dir, leaf)?),
                "configuration file changed"
            );
            out.identities.insert(path.clone(), identity(&m));
            out.logical.insert(
                path,
                Logical {
                    directory: false,
                    mode: m.mode() & 0o777 & !0o020,
                    bytes,
                    sha256: format!("{:x}", h.finalize()),
                    mtime: m.mtime(),
                    mtime_ns: m.mtime_nsec(),
                },
            );
        }
    }
    ensure!(
        children == names(dir)? && identity(&before) == identity(&dir.metadata()?),
        "configuration directory changed during census"
    );
    Ok(())
}
pub fn snapshot(dir: &File, uid: u32) -> Result<Snapshot> {
    capture(dir, uid, None)
}
fn capture(dir: &File, uid: u32, sole_source_gid: Option<u32>) -> Result<Snapshot> {
    let device = dir.metadata()?.dev();
    let mut out = Snapshot {
        identities: BTreeMap::new(),
        logical: BTreeMap::new(),
        bytes: 0,
    };
    snapshot_at(dir, "", device, uid, sole_source_gid, 0, &mut out)?;
    Ok(out)
}
fn mkdir(parent: &File, leaf: &str) -> Result<File> {
    let c = name(leaf)?;
    ensure!(
        unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } == 0,
        "configuration stage/directory is occupied or cannot be created"
    );
    child(parent, leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}
fn finish(file: &File, logical: &Logical, uid: u32, gid: u32) -> Result<()> {
    ensure!(
        unsafe { libc::fchmod(file.as_raw_fd(), logical.mode) } == 0,
        "cannot preserve configuration mode"
    );
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: logical.mtime,
            tv_nsec: logical.mtime_ns,
        },
    ];
    ensure!(
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } == 0,
        "cannot preserve configuration modification time"
    );
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "cannot assign isolated configuration owner"
    );
    file.sync_all()?;
    Ok(())
}
fn copy_at(
    source: &File,
    target: &File,
    prefix: &str,
    expected: &Snapshot,
    uid: u32,
    gid: u32,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "copy depth exceeded");
    ensure!(
        expected.identities.get(prefix) == Some(&identity(&source.metadata()?)),
        "source directory changed before copy"
    );
    for leaf in names(source)? {
        let path = if prefix.is_empty() {
            leaf.clone()
        } else {
            format!("{prefix}/{leaf}")
        };
        let expected_id = expected
            .identities
            .get(&path)
            .context("new source member during copy")?;
        let logical = expected
            .logical
            .get(&path)
            .context("missing logical source member")?;
        ensure!(
            *expected_id == identity(&metadata(source, &leaf)?),
            "source member changed before copy"
        );
        if logical.directory {
            let input = child(source, &leaf, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let output = mkdir(target, &leaf)?;
            copy_at(&input, &output, &path, expected, uid, gid, depth + 1)?;
        } else {
            let mut input = child(source, &leaf, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
            ensure!(
                *expected_id == identity(&input.metadata()?),
                "source file replaced at copy"
            );
            let mut output = child(
                target,
                &leaf,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let mut hash = Sha256::new();
            let mut bytes = 0u64;
            let mut buffer = [0u8; 64 << 10];
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                bytes += n as u64;
                ensure!(bytes <= logical.bytes, "source grew during copy");
                output.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
            }
            ensure!(
                bytes == logical.bytes
                    && format!("{:x}", hash.finalize()) == logical.sha256
                    && *expected_id == identity(&input.metadata()?)
                    && *expected_id == identity(&metadata(source, &leaf)?),
                "source changed during copy"
            );
            finish(&output, logical, uid, gid)?;
        }
    }
    finish(
        target,
        expected
            .logical
            .get(prefix)
            .context("missing copied directory")?,
        uid,
        gid,
    )?;
    Ok(())
}
/// Occupied or interrupted stages always fail closed. Only a NEW no-clobber name
/// can begin another attempt; this primitive never removes old credential files.
#[cfg(test)]
pub fn copy_stage(
    source: &File,
    parent: &File,
    leaf: &str,
    source_uid: u32,
    target_uid: u32,
    target_gid: u32,
    after_before: impl FnOnce() -> Result<()>,
) -> Result<Snapshot> {
    copy_stage_profile(
        source,
        parent,
        leaf,
        source_uid,
        target_uid,
        target_gid,
        None,
        after_before,
    )
}
/// Root's wrapper must authenticate the sole-member review before selecting
/// this source-only 0775 directory allowance. It is never applied to targets.
#[allow(clippy::too_many_arguments)]
pub fn copy_stage_profile(
    source: &File,
    parent: &File,
    leaf: &str,
    source_uid: u32,
    target_uid: u32,
    target_gid: u32,
    sole_source_gid: Option<u32>,
    after_before: impl FnOnce() -> Result<()>,
) -> Result<Snapshot> {
    let before = capture(source, source_uid, sole_source_gid)?;
    after_before()?;
    let stage = mkdir(parent, leaf)?;
    copy_at(source, &stage, "", &before, target_uid, target_gid, 0)?;
    let after = capture(source, source_uid, sole_source_gid)?;
    ensure!(before == after, "source tree changed across coherent copy");
    let target = snapshot(&stage, target_uid)?;
    ensure!(
        before.logical_equals(&target),
        "copied configuration differs in bytes/modes/mtime"
    );
    parent.sync_all()?;
    Ok(before)
}
