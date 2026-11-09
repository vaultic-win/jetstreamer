use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}
pub fn hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
pub fn bytes(b: &Bound, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    crate::deny_original199(&b.path)?;
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path && hex(&b.sha256, 64),
        "metadata binding shape"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&b.path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.len() <= limit
            && before.mode() & 0o022 == 0
            && (!immutable || before.mode() & 0o222 == 0),
        "metadata custody/bound"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(limit + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == before.len()
            && sha(&raw) == b.sha256
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&b.path)?),
        "metadata changed/digest mismatch"
    );
    Ok(raw)
}
pub fn json(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bytes(b, 32 << 20, false)?)?)
}
pub fn bound(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
pub fn n(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
pub fn save(root: &Path, name: &str, v: &Value) -> Result<Bound> {
    ensure!(
        !name.contains('/') && name.ends_with(".json"),
        "output leaf"
    );
    let p = root.join(name);
    let mut raw = serde_json::to_vec_pretty(v)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 16 << 20, "planned metadata too large");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)?;
    f.write_all(&raw)?;
    f.set_permissions(fs::Permissions::from_mode(0o444))?;
    f.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(Bound {
        path: p,
        sha256: sha(&raw),
    })
}
