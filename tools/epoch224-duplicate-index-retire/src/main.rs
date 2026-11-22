//! Exact local retirement of specific closed epoch 224 CID-index copies.
//! Closed profile registry; no recursive removal, service mutation or R2 routes.
mod execution;
mod process_references;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
};
const DEV: u64 = 66305;
const LIMIT: u64 = 8 << 20;
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const DEPLOY: &str = "/var/lib/jetstreamer/horizon224-index-retirer-v169-v1";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    blocks: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(m: &fs::Metadata) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        len: m.len(),
        blocks: m.blocks(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("expected absent exact path: {}", p.display()),
    }
}
fn file_bytes(
    p: &Path,
    expected: &str,
    uid: u32,
    ino: Option<u64>,
    immutable: bool,
) -> Result<Vec<u8>> {
    ensure!(digest(expected), "digest syntax");
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == uid
            && m.gid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0)
            && m.len() <= LIMIT
            && ino.is_none_or(|i| i == m.ino())
            && (uid != 1000 || (m.dev() == DEV && m.mode() & 0o7777 == 0o600)),
        "file custody: {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(stamp(&f.metadata()?) == stamp(&m), "file open race");
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(LIMIT + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= LIMIT
            && sha(&raw) == expected
            && stamp(&f.metadata()?) == stamp(&m)
            && stamp(&fs::symlink_metadata(p)?) == stamp(&m),
        "file changed/hash mismatch"
    );
    Ok(raw)
}
fn write_new(p: &Path, v: &Value) -> Result<Bound> {
    let raw = serde_json::to_vec_pretty(v)?;
    ensure!(raw.len() as u64 <= LIMIT, "receipt limit");
    let parent = p.parent().context("receipt parent")?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .mode(0o444)
        .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
        .open(parent)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    let parent_fd = File::open(parent)?;
    let source = std::ffi::CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))?;
    let name = std::ffi::CString::new(p.file_name().context("receipt name")?.as_encoded_bytes())?;
    // Publish the fully synced anonymous inode. An interrupted write leaves no
    // named partial receipt, and linkat cannot replace an existing name.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent_fd.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    parent_fd.sync_all()?;
    Ok(Bound {
        path: p.into(),
        sha256: sha(&raw),
    })
}
fn lock() -> Result<File> {
    let p = Path::new(LOCK);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.nlink() == 1
            && [0, 1000].contains(&m.uid())
            && m.mode() & 0o077 == 0,
        "shared mutation lock custody"
    );
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    ensure!(
        stamp(&f.metadata()?) == stamp(&m)
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "mutation lock race/busy"
    );
    Ok(f)
}

#[derive(Deserialize, Serialize, Clone)]
struct Artifact {
    path: PathBuf,
    stamp: Stamp,
}
#[derive(Deserialize, Serialize, Clone)]
struct Profile {
    selection: String,
    target: PathBuf,
    target_identity: Stamp,
    target_parent_inode: u64,
    retained: Artifact,
    protected: Vec<Artifact>,
    custody: Vec<Bound>,
    root: PathBuf,
    unit: String,
    iid: String,
    header_hex: String,
}
fn ancestors(p: &Path) -> Result<()> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical path"
    );
    for a in p.ancestors().skip(1) {
        let m = fs::symlink_metadata(a)?;
        ensure!(
            m.is_dir() && [0, 1000].contains(&m.uid()) && m.mode() & 0o022 == 0,
            "unsafe path ancestor {}",
            a.display()
        );
    }
    Ok(())
}
fn exact(p: &Path, want: &Stamp) -> Result<()> {
    ancestors(p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && stamp(&m) == *want,
        "exact file identity changed {}",
        p.display()
    );
    Ok(())
}
fn parent_fd(q: &Profile) -> Result<File> {
    let p = q.target.parent().context("target parent")?;
    ancestors(p)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.dev() == q.target_identity.dev
            && m.ino() == q.target_parent_inode
            && m.uid() == 1000
            && m.gid() == 1000
            && m.mode() & 0o7777 == 0o700,
        "original cache parent changed"
    );
    Ok(f)
}
fn read_bounded(p: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    File::open(p)?.take(limit + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 <= limit,
        "bounded read exceeded {}",
        p.display()
    );
    Ok(b)
}
fn unescape(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        if b[i] == b'\\' {
            ensure!(i + 3 < b.len(), "mount escape");
            let v = &b[i + 1..i + 4];
            ensure!(v.iter().all(|v| (b'0'..=b'7').contains(v)), "mount octal");
            let n = (v[0] - b'0') as u16 * 64 + (v[1] - b'0') as u16 * 8 + (v[2] - b'0') as u16;
            ensure!(n <= 255, "mount escape overflow");
            out.push(n as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}
fn mount_check(raw: &str, target: &Path, dev: u64) -> Result<()> {
    for line in raw.lines() {
        let w: Vec<_> = line.split_whitespace().collect();
        ensure!(w.len() >= 10 && w.contains(&"-"), "mountinfo framing");
        let root = PathBuf::from(unescape(w[3])?);
        let point = PathBuf::from(unescape(w[4])?);
        ensure!(
            !(point == target || point.starts_with(target)),
            "target mountpoint"
        );
        if w[2] == format!("{}:{}", libc::major(dev), libc::minor(dev)) {
            ensure!(
                !(root == target || root.starts_with(target)),
                "target mount alias"
            );
            if let Ok(suffix) = target.strip_prefix(&root) {
                ensure!(point.join(suffix) == target, "ancestor mount alias");
            }
        }
    }
    Ok(())
}
fn inode_match(m: &fs::Metadata, q: &Profile) -> bool {
    m.dev() == q.target_identity.dev
        && [q.target_identity.ino, q.target_parent_inode].contains(&m.ino())
}
fn start(p: &Path) -> Result<String> {
    let bytes = read_bounded(&p.join("stat"), 65536)?;
    let s = std::str::from_utf8(&bytes)?;
    Ok(s.rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc start")?
        .into())
}
fn maps_inodes(p: &Path, q: &Profile) -> Result<()> {
    let f = File::open(p)?;
    let mut reader = BufReader::with_capacity(65536, f);
    let mut total = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.by_ref().take(1 << 20).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        ensure!(n < 1 << 20, "oversized map line");
        total += n as u64;
        ensure!(total <= 1 << 30, "maps bound");
        let text = std::str::from_utf8(&line)?;
        let w: Vec<_> = text.split_whitespace().take(5).collect();
        ensure!(w.len() == 5, "maps framing");
        let (major, minor) = w[3].split_once(':').context("map device")?;
        let dev = libc::makedev(
            u32::from_str_radix(major, 16)?,
            u32::from_str_radix(minor, 16)?,
        );
        let ino = w[4].parse::<u64>()?;
        ensure!(
            dev != q.target_identity.dev
                || ![q.target_identity.ino, q.target_parent_inode].contains(&ino),
            "mapped target inode alias"
        );
    }
    Ok(())
}
fn process_closure(q: &Profile) -> Result<Value> {
    let target_parent = q.target.parent().context("cache parent")?;
    let scan = process_references::scan(Path::new("/proc"), target_parent)?;
    ensure!(
        scan.references.is_empty(),
        "original cache has live references: {:?}",
        scan.references
    );
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let n = entry.file_name();
        let name = n.to_string_lossy();
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_digit())
            || name == std::process::id().to_string()
        {
            continue;
        }
        let p = entry.path();
        let check = || -> Result<()> {
            let before = start(&p)?;
            maps_inodes(&p.join("maps"), q)?;
            let mounts = read_bounded(&p.join("mountinfo"), 16 << 20)?;
            mount_check(
                std::str::from_utf8(&mounts)?,
                &q.target,
                q.target_identity.dev,
            )?;
            for link in ["cwd", "root", "exe"] {
                match fs::metadata(p.join(link)) {
                    Ok(m) => ensure!(!inode_match(&m, q), "process inode alias"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m) => ensure!(!inode_match(&m, q), "open inode alias"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            ensure!(before == start(&p)?, "PID reused during alias scan");
            Ok(())
        };
        if let Err(e) = check()
            && p.try_exists()?
        {
            return Err(e);
        }
        count += 1;
    }
    mount_check(
        std::str::from_utf8(&read_bounded(Path::new("/proc/self/mountinfo"), 16 << 20)?)?,
        &q.target,
        q.target_identity.dev,
    )?;
    Ok(json!({"path_scan":scan,"inode_mount_scan_processes":count}))
}

fn main() -> Result<()> {
    execution::run()
}
