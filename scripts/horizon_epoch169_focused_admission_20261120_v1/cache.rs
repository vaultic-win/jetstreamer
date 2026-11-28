//! The failed worker finished the two slot indexes and left an empty runtime directory.
//! Its CID index lives in the separately charged standard lane and is projected read-only.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub const SOURCE: &str =
    "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/output/compact-indexes/169";
pub const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1/v158/compact-indexes/169";
pub const CID: &str = "epoch-169-bafyreibnyugrtsptq5qsj6tdweurgpzl55f75t7ku5r7wpxtia6e7gojbm-mainnet-cid-to-offset-and-size.index";
const SLOT169: &str = "epoch-169-bafyreibnyugrtsptq5qsj6tdweurgpzl55f75t7ku5r7wpxtia6e7gojbm-mainnet-slot-to-cid.index";
const SLOT168: &str = "epoch-168-bafyreigrdukjoi2647fzy7dbzbxcqygm54vogb6pbhhjhi6lowooruvnxa-mainnet-slot-to-cid.index";
const SLOT169_SHA: &str = "e8516d5682a15a53eeb978db80eb1a2542ec54720265a5f21c7fe43244068b4d";

fn entries(dir: &Path, expected: &[&str]) -> Result<()> {
    let actual = fs::read_dir(dir)?
        .map(|item| {
            item?
                .file_name()
                .into_string()
                .map_err(|_| io::Error::other("invalid cache filename"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    ensure!(
        actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "unexpected entries at {}",
        dir.display()
    );
    Ok(())
}
fn directory(p: &Path, ino: u64) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_dir()
            && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777)
                == (64512, ino, 1001, 1003, 0o700),
        "cache directory custody {}",
        p.display()
    );
    Ok(())
}
fn file(p: &Path, ino: u64, bytes: u64) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode() & 0o7777,
                m.nlink(),
                m.len()
            ) == (64512, ino, 1001, 1003, 0o600, 1, bytes),
        "cache file custody {}",
        p.display()
    );
    Ok(f)
}
fn slot(p: &Path, ino: u64, bytes: u64, digest: &str) -> Result<()> {
    let mut f = file(p, ino, bytes)?;
    let mut h = Sha256::new();
    ensure!(
        io::copy(&mut f, &mut h)? == bytes && format!("{:x}", h.finalize()) == digest,
        "slot index changed {}",
        p.display()
    );
    Ok(())
}
pub fn scratch(p: &Path) -> Result<()> {
    directory(p, 114230961)?;
    entries(p, &[".historical-runtime"])?;
    let runtime = p.join(".historical-runtime");
    directory(&runtime, 114235485)?;
    entries(&runtime, &[])
}
pub fn host_cache(dest: &Path) -> Result<()> {
    let root = dest.join("compact-indexes");
    directory(&root, 114556935)?;
    entries(&root, &["168", "169"])?;
    let prior = root.join("168");
    directory(&prior, 114556936)?;
    entries(&prior, &[SLOT168])?;
    slot(
        &prior.join(SLOT168),
        114556937,
        15_210_704,
        "17c705d901c6eaa710998b6706d06a892d16273e05227848a515870544ed4097",
    )?;
    let original = root.join("169");
    directory(&original, 114556938)?;
    entries(&original, &[SLOT169])?;
    slot(&original.join(SLOT169), 114556940, 15_250_890, SLOT169_SHA)?;
    projected(Path::new(SOURCE))
}
pub fn projected(p: &Path) -> Result<()> {
    directory(p, 105775171)?;
    entries(p, &[CID, SLOT169])?;
    slot(&p.join(SLOT169), 105775778, 15_250_890, SLOT169_SHA)?;
    let mut index = file(&p.join(CID), 105775786, 4_322_853_290)?;
    let m = index.metadata()?;
    // The full upstream comparison binds both timestamps on this inode. ctime also
    // detects writes followed by restoring mtime.
    ensure!(
        (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec())
            == (1794254702, 708567274, 1794254702, 935568306),
        "verified CID index changed"
    );
    let mut magic = [0u8; 8];
    index
        .read_exact(&mut magic)
        .context("read compact index header")?;
    ensure!(&magic == b"compiszd", "compact index signature");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unexpected_partial_or_missing_entry_fails() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(entries(tmp.path(), &["index"]).is_err());
        fs::write(tmp.path().join("index"), b"").unwrap();
        entries(tmp.path(), &["index"]).unwrap();
        fs::write(tmp.path().join(".partial"), b"").unwrap();
        assert!(entries(tmp.path(), &["index"]).is_err());
    }
}
