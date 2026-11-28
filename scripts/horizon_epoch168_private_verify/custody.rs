use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Stamp {
    dev: u64,
    ino: u64,
    pub len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn stamp(m: Metadata) -> Result<Stamp> {
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "expected one immutable root-owned regular file"
    );
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        nlink: m.nlink(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}

pub struct Opened {
    path: PathBuf,
    file: File,
    pub start: Stamp,
}

impl Opened {
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute() && fs::canonicalize(path)? == path,
            "noncanonical path {}",
            path.display()
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let start = stamp(file.metadata()?).with_context(|| path.display().to_string())?;
        let opened = Self {
            path: path.to_owned(),
            file,
            start,
        };
        opened.unchanged()?;
        Ok(opened)
    }

    pub fn unchanged(&self) -> Result<()> {
        ensure!(
            self.start == stamp(self.file.metadata()?)?
                && self.start == stamp(fs::symlink_metadata(&self.path)?)?
                && fs::canonicalize(&self.path)? == self.path,
            "file identity changed: {}",
            self.path.display()
        );
        Ok(())
    }

    pub fn hash(&mut self) -> Result<String> {
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            let before = total;
            total = total.checked_add(n as u64).context("byte count overflow")?;
            ensure!(total <= self.start.len, "file grew while hashing");
            if total >> 32 != before >> 32 {
                eprintln!("archive digest checked {total} bytes");
            }
        }
        ensure!(total == self.start.len, "file truncated while hashing");
        self.unchanged()?;
        Ok(format!("{:x}", h.finalize()))
    }
}

impl Bound {
    pub fn json(&self) -> Result<Value> {
        ensure!(
            is_digest(&self.sha256),
            "invalid SHA-256 for {}",
            self.path.display()
        );
        let mut f = Opened::open(&self.path)?;
        ensure!(
            f.start.len <= 4 * 1024 * 1024,
            "document too large: {}",
            self.path.display()
        );
        let mut bytes = Vec::with_capacity(f.start.len as usize);
        (&mut f.file)
            .take(f.start.len + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == f.start.len && digest(&bytes) == self.sha256,
            "wrong document digest: {}",
            self.path.display()
        );
        f.unchanged()?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn binary(&self) -> Result<()> {
        ensure!(
            Opened::open(&self.path)?.hash()? == self.sha256,
            "wrong binary: {}",
            self.path.display()
        );
        Ok(())
    }
}

pub fn bound(path: &Path) -> Result<Bound> {
    Ok(Bound {
        path: path.to_owned(),
        sha256: Opened::open(path)?.hash()?,
    })
}

pub fn reference(doc: &Value, field: &str) -> Result<Bound> {
    Ok(serde_json::from_value(
        doc.get(field)
            .with_context(|| format!("missing {field}"))?
            .clone(),
    )?)
}

pub fn num(doc: &Value, field: &str) -> Result<u64> {
    doc[field]
        .as_u64()
        .with_context(|| format!("missing number {field}"))
}

pub fn string<'a>(doc: &'a Value, field: &str) -> Result<&'a str> {
    doc[field]
        .as_str()
        .with_context(|| format!("missing string {field}"))
}

pub fn save(path: &Path, value: &Value) -> Result<Bound> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    File::open(path.parent().context("result parent")?)?.sync_all()?;
    bound(path)
}
