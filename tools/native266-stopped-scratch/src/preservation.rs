//! Stream already-closed originals through a pinned OS checksum utility, for the Main-only
//! initial preservation or read-only closure phase. No replay, publication or write mode.
pub(crate) use crate::profile::RUN;
use crate::profile::{
    ARCHIVE_INODE, ARCHIVE_MTIME, ARCHIVE_SHA, ARCHIVE_SIZE, DEVICE, STATE_INODE, STATE_MTIME,
};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const HASHER: &str = "/usr/bin/sha256sum";
pub const HASHER_SHA256: &str = "27a7d8f6a005702618e92c88f20b829d38247ad3369e0c35b1ff219d15194bd1";
const STATE_SHA: &str = "2c9c246126a8878f8e11928858512f8ef881a6a794118c04d1a1572b18427c87";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub len: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}
impl From<&Metadata> for Stamp {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            nlink: m.nlink(),
            len: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Member {
    pub path: PathBuf,
    pub original: Stamp,
    pub sha256: String,
}
fn need(ok: bool, msg: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(msg))
    }
}
fn open(p: &Path) -> io::Result<(File, Stamp)> {
    need(p.canonicalize()? == p, "noncanonical path")?;
    let m = fs::symlink_metadata(p)?;
    let st = Stamp::from(&m);
    need(m.is_file() && m.nlink() == 1, "non-regular or linked file")?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(0o400000 | 0o1000000)
        .open(p)?; // O_NOFOLLOW | O_NOATIME
    need(st == Stamp::from(&f.metadata()?), "rebound source")?;
    Ok((f, st))
}
pub(crate) fn digest(f: &File) -> io::Result<String> {
    // The containing deployment checks HASHER_SHA256 and immutable /usr/bin/sha256sum
    // custody on its first guard. Only an already-open source handle is exposed.
    let o = Command::new(HASHER)
        .arg("--binary")
        .stdin(Stdio::from(f.try_clone()?))
        .output()?;
    need(
        o.status.success() && o.stdout.len() == 68 && o.stdout.ends_with(b" *-\n"),
        "checksum output",
    )?;
    let s = std::str::from_utf8(&o.stdout[..64]).map_err(io::Error::other)?;
    need(
        s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "SHA-256 syntax",
    )?;
    Ok(s.to_owned())
}
fn stable(path: &Path, f: &File, before: &Stamp) -> io::Result<()> {
    need(
        Stamp::from(&f.metadata()?) == *before
            && Stamp::from(&fs::symlink_metadata(path)?) == *before
            && path.canonicalize()? == path,
        "source changed during stream",
    )
}
fn original(name: &str, ino: u64, size: u64, mtime_ns: i64) -> io::Result<Member> {
    let p = Path::new(RUN).join(name);
    let (f, st) = open(&p)?;
    need(
        (st.dev, st.ino, st.len, st.mode, st.uid, st.gid)
            == (DEVICE, ino, size, 0o100600, 1000, 1000)
            && st.mtime == st.ctime
            && st.mtime == (mtime_ns / 1_000_000_000, mtime_ns % 1_000_000_000),
        "wrong original producer object",
    )?;
    let sha = digest(&f)?;
    stable(&p, &f, &st)?;
    Ok(Member {
        path: p,
        original: st,
        sha256: sha,
    })
}
/// Hash both retained originals from already-open descriptors and verify their recorded identities.
pub fn originals() -> io::Result<[Member; 2]> {
    // The distribution installs a root-owned multicall executable behind this symlink.
    // Its link count differs from the producer's exclusively owned private files.
    let utility = Path::new(HASHER).canonicalize()?;
    need(
        utility == Path::new("/usr/lib/cargo/bin/coreutils/sha256sum"),
        "checksum target",
    )?;
    let hasher = File::open(&utility)?;
    let stamp = Stamp::from(&hasher.metadata()?);
    need(
        hasher.metadata()?.is_file()
            && stamp.uid == 0
            && stamp.mode & 0o022 == 0
            && digest(&hasher)? == HASHER_SHA256,
        "checksum utility identity",
    )?;
    stable(&utility, &hasher, &stamp)?;
    let state = original("cohort-state.json", STATE_INODE, 222, STATE_MTIME)?;
    need(state.sha256 == STATE_SHA, "cohort state changed")?;
    let archive = original(
        "archives/epoch-266.jet",
        ARCHIVE_INODE,
        ARCHIVE_SIZE,
        ARCHIVE_MTIME,
    )?;
    need(archive.sha256 == ARCHIVE_SHA, "partial archive changed")?;
    Ok([archive, state])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_of_empty_closed_file() -> io::Result<()> {
        let f = File::open("/dev/null")?;
        assert_eq!(
            digest(&f)?,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        Ok(())
    }
}
