//! Owned high-priority PID1 masks shared by the standard 169 lease consumers.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, fs, io::ErrorKind, os::unix::fs::MetadataExt, path::Path};

pub const HIGH: &str = "/run/systemd/system.control";

pub fn safe_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && path.canonicalize()? == path && m.uid() == 0 && m.mode() & 0o022 == 0,
        "unsafe fence dir {}",
        path.display()
    );
    Ok(())
}
pub fn id(path: &Path) -> Result<(u64, u64)> {
    let m = fs::symlink_metadata(path)?;
    Ok((m.dev(), m.ino()))
}
pub fn linked_to(path: &Path, anchor: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(m.file_type().is_symlink()
            && m.uid() == 0
            && id(path)? == id(anchor)?
            && fs::read_link(path)? == Path::new("/dev/null")),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
/// Every existing entry must belong to the exact anchor. None checks that
/// there are no fragments before a fresh transaction owns a mask inode.
pub fn check_destinations(
    dir: &Path,
    anchor: Option<&Path>,
    units: &BTreeSet<String>,
) -> Result<()> {
    for u in units {
        let dst = dir.join(u);
        match fs::symlink_metadata(&dst) {
            Ok(_) => ensure!(
                anchor.map_or(Ok(false), |path| linked_to(&dst, path))?,
                "existing foreign unit fragment at {u}"
            ),
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn install_links(dir: &Path, anchor: &Path, units: &BTreeSet<String>) -> Result<()> {
    for u in units {
        let dst = dir.join(u);
        if !linked_to(&dst, anchor)? {
            fs::hard_link(anchor, &dst)
                .with_context(|| format!("preexisting foreign mask/fragment for {u}"))?;
        }
    }
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_transaction_rejects_preexisting_fragment_without_touching_it() {
        let fixture = tempfile::tempdir().unwrap();
        let service = "horizon-qualify-169-standard-fixture.service";
        let units = BTreeSet::from([service.to_owned()]);
        check_destinations(fixture.path(), None, &units).unwrap();
        let fragment = fixture.path().join(service);
        fs::write(&fragment, b"foreign fixture").unwrap();
        assert!(check_destinations(fixture.path(), None, &units).is_err());
        assert_eq!(fs::read(fragment).unwrap(), b"foreign fixture");
    }
}
