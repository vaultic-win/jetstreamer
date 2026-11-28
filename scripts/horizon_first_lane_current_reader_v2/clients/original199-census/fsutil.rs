use crate::model::Bound;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};
pub fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
pub fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
pub fn open(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "noncanonical path"
    );
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let parts = path.components().collect::<Vec<_>>();
    let mut prefix = PathBuf::from("/");
    ensure!(parts.len() > 1, "root is not evidence");
    for (i, c) in parts.iter().enumerate().skip(1) {
        let Component::Normal(name) = c else {
            anyhow::bail!("bad component")
        };
        prefix.push(name);
        let name = std::ffi::CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if i + 1 < parts.len() {
                        libc::O_DIRECTORY
                    } else {
                        0
                    },
            )
        };
        ensure!(
            fd >= 0,
            "no-follow evidence traversal failed: {}",
            std::io::Error::last_os_error()
        );
        dir = unsafe { File::from_raw_fd(fd) };
        if i + 1 < parts.len() {
            let m = dir.metadata()?;
            ensure!(
                m.is_dir()
                    && ((m.uid() == 0 && m.mode() & 0o022 == 0)
                        || (prefix == Path::new("/home/sol")
                            && m.uid() == 1001
                            && m.mode() & 0o022 == 0)
                        || (prefix == Path::new("/home/sol/.jetstreamer-private")
                            && m.uid() == 1001
                            && m.mode() & 0o777 == 0o700)),
                "foreign/writable ancestor"
            );
        }
    }
    Ok(dir)
}
pub fn bytes(b: &Bound, max: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(hex(&b.sha256, 64), "invalid digest");
    let mut f = open(&b.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.len() > 0
            && m.len() <= max
            && m.mode() & 0o022 == 0
            && (!immutable || m.mode() & 0o222 == 0),
        "root regular bounded evidence custody differs"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take(max.checked_add(1).context("size overflow")?)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == m.len()
            && sha(&raw) == b.sha256
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&open(&b.path)?.metadata()?),
        "evidence replaced/changed or digest differs"
    );
    Ok(raw)
}
pub fn json(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, 32 << 20, false)?)?)
}
pub fn immutable(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, 32 << 20, true)?)?)
}
pub fn fresh(at: u64, now: u64, max: u64) -> Result<()> {
    ensure!(
        at > 0 && now.checked_sub(at).is_some_and(|n| n <= max),
        "future/stale evidence"
    );
    Ok(())
}
pub fn bound(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
pub fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing integer {k}"))
}
