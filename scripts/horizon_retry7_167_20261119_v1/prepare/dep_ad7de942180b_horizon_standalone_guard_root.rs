//! Optional own-tree physical budget, independent of other lanes' allocations.
//! Walk stable directory descriptors without following child symlinks.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    time::{Duration, Instant},
};

const MAX_ENTRIES: u64 = 8_000_000;
const MAX_DEPTH: u32 = 128;
#[derive(Default, Debug, Serialize)]
pub(super) struct Scan {
    physical_bytes: u64,
    entries: u64,
    vanished_entries: u64,
    directories: u64,
    symlinks: u64,
}
#[derive(Debug, Serialize)]
pub(super) struct Observation {
    pub conservative_physical_bytes: u64,
    pub maximum_physical_bytes: u64,
    pub exceeds_budget: bool,
    first: Scan,
    second: Scan,
}
fn directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn account(m: &fs::Metadata, dev: u64, s: &mut Scan) -> Result<()> {
    ensure!(
        m.dev() == dev,
        "physical budget encountered another filesystem"
    );
    s.entries = s.entries.checked_add(1).context("entry overflow")?;
    ensure!(
        s.entries <= MAX_ENTRIES,
        "physical scan entry bound exceeded"
    );
    // Counting multiply linked entries more than once is conservative. Do not
    // assume apparent lengths or traverse links to find their targets.
    s.physical_bytes = s
        .physical_bytes
        .checked_add(
            m.blocks()
                .checked_mul(512)
                .context("physical block overflow")?,
        )
        .context("physical total overflow")?;
    Ok(())
}
fn walk(fd: &File, dev: u64, depth: u32, s: &mut Scan, deadline: Instant) -> Result<()> {
    ensure!(
        depth <= MAX_DEPTH && Instant::now() < deadline,
        "physical scan depth/time bound exceeded"
    );
    let meta = fd.metadata()?;
    ensure!(meta.is_dir(), "physical scan descriptor is not a directory");
    account(&meta, dev, s)?;
    s.directories += 1;
    let anchored = std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    for item in fs::read_dir(&anchored)? {
        ensure!(
            Instant::now() < deadline,
            "physical scan time bound exceeded"
        );
        let path = item?.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                s.vanished_entries += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if meta.is_dir() {
            let child = match directory(&path) {
                Ok(f) => f,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    s.vanished_entries += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            walk(&child, dev, depth + 1, s, deadline)?;
        } else {
            account(&meta, dev, s)?;
            if meta.file_type().is_symlink() {
                s.symlinks += 1;
            }
        }
    }
    Ok(())
}
pub(super) fn observe(root: &Path, maximum: u64) -> Result<Observation> {
    ensure!(maximum > 0, "physical budget must be nonzero");
    ensure!(
        root.is_absolute() && root.canonicalize()? == root,
        "physical root is noncanonical"
    );
    let file = directory(root)?;
    let initial = file.metadata()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut first = Scan::default();
    walk(&file, initial.dev(), 0, &mut first, deadline)?;
    let mut second = Scan::default();
    walk(&file, initial.dev(), 0, &mut second, deadline)?;
    let path = fs::symlink_metadata(root)?;
    ensure!(
        path.is_dir()
            && path.dev() == initial.dev()
            && path.ino() == initial.ino()
            && root.canonicalize()? == root,
        "physical budget root changed during scan"
    );
    let conservative = first.physical_bytes.max(second.physical_bytes);
    Ok(Observation {
        conservative_physical_bytes: conservative,
        maximum_physical_bytes: maximum,
        exceeds_budget: conservative > maximum,
        first,
        second,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn measures_own_allocations_not_apparent_size_or_other_lanes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let own = root.join("own");
        fs::write(&own, vec![7; 16 * 1024]).unwrap();
        let sparse = File::create(root.join("sparse")).unwrap();
        sparse.set_len(1 << 40).unwrap();
        let a = observe(&root, 1 << 20).unwrap();
        assert!(!a.exceeds_budget);
        fs::write(temp.path().join("other-lane"), vec![9; 1024 * 1024]).unwrap();
        let b = observe(&root, 1 << 20).unwrap();
        assert_eq!(a.conservative_physical_bytes, b.conservative_physical_bytes);
        let small = observe(&root, 4096).unwrap();
        assert!(small.exceeds_budget);
        assert!(small.conservative_physical_bytes >= 16 * 1024);
    }
    #[test]
    fn never_follows_symlinks_and_rejects_symlink_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("large"), vec![1; 1024 * 1024]).unwrap();
        symlink(&outside, root.join("external")).unwrap();
        symlink(&root, root.join("cycle")).unwrap();
        let v = observe(&root, 1 << 20).unwrap();
        assert!(!v.exceeds_budget);
        assert_eq!(v.first.symlinks, 2);
        assert_eq!(v.first.directories, 1);
        let link = temp.path().join("link");
        symlink(&root, &link).unwrap();
        assert!(observe(&link, 1 << 20).is_err());
        assert!(observe(&root, 0).is_err());
    }
    #[test]
    fn unexpected_depth_fails_closed_instead_of_partial_accounting() {
        let temp = tempfile::tempdir().unwrap();
        let mut path = temp.path().to_path_buf();
        for _ in 0..MAX_DEPTH + 1 {
            path = path.join("d");
            fs::create_dir(&path).unwrap();
        }
        assert!(observe(temp.path(), 1 << 30).is_err());
    }
}
