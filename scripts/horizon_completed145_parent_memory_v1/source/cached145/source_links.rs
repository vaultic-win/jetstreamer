//! The four installed unit links retain their original logical bindings. Read
//! only their exact normally sealed targets; ordinary evidence stays no-follow.
use crate::{fsutil as f, model::Bound};
use anyhow::{Result, ensure};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

const STARTUP: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch145-cached-b2a09f57de39c384-startup-units-20261101-v1";
const GUARDS: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch145-cached-b2a09f57de39c384-guard-units-20261101-v1";
const STARTUP_SEAL: &str = "bff477c171c5b6e5d584ea62fd553695b12d117a7287467049a4f3a0a84efea9";
const GUARD_SEAL: &str = "1b9275a44884d1ae74fdf3370c60879d3939e5a9d82ef4c232e24194fe3c5ba1";

fn declared_alias(b: &Bound) -> Result<Option<(Bound, Bound)>> {
    let Some(i) = super::SOURCES[..4]
        .iter()
        .position(|(path, _)| b.path == Path::new(path))
    else {
        return Ok(None);
    };
    ensure!(
        b.sha256 == super::SOURCES[i].1,
        "installed unit link digest differs"
    );
    let (dir, seal) = if i == 0 {
        (STARTUP, STARTUP_SEAL)
    } else {
        (GUARDS, GUARD_SEAL)
    };
    let name = b.path.file_name().expect("declared absolute unit path");
    Ok(Some((
        Bound {
            path: Path::new(dir).join(name),
            sha256: b.sha256.clone(),
        },
        Bound {
            path: Path::new(dir).join("deployment-seal-receipt.json"),
            sha256: seal.into(),
        },
    )))
}
fn checked_target(actual: &Path, expected: &Path) -> Result<()> {
    ensure!(
        actual == expected && actual.is_absolute(),
        "installed unit link target differs"
    );
    Ok(())
}
fn checked_owner(is_link: bool, uid: u32, gid: u32, links: u64) -> Result<()> {
    ensure!(
        is_link && uid == 0 && gid == 0 && links == 1,
        "installed unit link custody differs"
    );
    Ok(())
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
pub(super) fn bytes(b: &Bound) -> Result<Vec<u8>> {
    let Some((target, seal)) = declared_alias(b)? else {
        return f::bytes(b, 128 << 20, false);
    };
    let parent = b.path.parent().expect("declared unit parent");
    let dir = f::open(parent)?.metadata()?;
    ensure!(
        dir.is_dir() && dir.uid() == 0 && dir.gid() == 0 && dir.mode() & 0o022 == 0,
        "installed unit link directory custody differs"
    );
    let before = fs::symlink_metadata(&b.path)?;
    checked_owner(
        before.is_symlink(),
        before.uid(),
        before.gid(),
        before.nlink(),
    )?;
    checked_target(&fs::read_link(&b.path)?, &target.path)?;
    crate::sealed_member(&f::immutable(&seal)?, &target, "0444")?;
    let raw = f::bytes(&target, 128 << 20, true)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(&b.path)?)
            && identity(&dir) == identity(&f::open(parent)?.metadata()?),
        "installed unit link or directory changed"
    );
    checked_target(&fs::read_link(&b.path)?, &target.path)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn binding(i: usize) -> Bound {
        Bound {
            path: super::super::SOURCES[i].0.into(),
            sha256: super::super::SOURCES[i].1.into(),
        }
    }
    #[test]
    fn only_four_original_unit_paths_have_sealed_aliases() {
        for i in 0..6 {
            let b = binding(i);
            let alias = declared_alias(&b).unwrap();
            assert_eq!(alias.is_some(), i < 4);
            if let Some((target, seal)) = alias {
                assert_eq!(target.path.file_name(), b.path.file_name());
                assert_eq!(target.sha256, b.sha256);
                assert_eq!(target.path.parent(), seal.path.parent());
                assert_eq!(
                    seal.path.file_name().unwrap(),
                    "deployment-seal-receipt.json"
                );
            }
        }
    }
    #[test]
    fn changed_logical_digest_cannot_choose_a_different_sealed_member() {
        for i in 0..4 {
            let mut b = binding(i);
            b.sha256 = "0".repeat(64);
            assert!(declared_alias(&b).is_err());
        }
        let mut b = binding(0);
        b.path = "/etc/systemd/system/foreign.service".into();
        assert!(declared_alias(&b).unwrap().is_none());
    }
    #[test]
    fn relative_traversing_and_foreign_targets_are_rejected() {
        let (target, _) = declared_alias(&binding(0)).unwrap().unwrap();
        checked_target(&target.path, &target.path).unwrap();
        for bad in [
            PathBuf::from("foreign.service"),
            PathBuf::from("/tmp/foreign.service"),
            target.path.parent().unwrap().join("../foreign.service"),
            Path::new(GUARDS).join(target.path.file_name().unwrap()),
        ] {
            assert!(checked_target(&bad, &target.path).is_err());
        }
    }
    #[test]
    fn foreign_owners_regular_files_and_multiple_links_are_rejected() {
        checked_owner(true, 0, 0, 1).unwrap();
        for (link, uid, gid, n) in [
            (false, 0, 0, 1),
            (true, 1001, 0, 1),
            (true, 0, 1001, 1),
            (true, 0, 0, 2),
        ] {
            assert!(checked_owner(link, uid, gid, n).is_err());
        }
    }
    #[test]
    #[ignore = "read-only qualification against the four installed cached145 unit links"]
    fn installed_links_match_exact_sealed_target_bytes() {
        for i in 0..4 {
            let b = binding(i);
            assert_eq!(f::sha(&bytes(&b).unwrap()), b.sha256);
        }
    }
}
