use super::*;

const BASE: &str = "/run/systemd/generator";

fn uses_reviewed_generators() -> bool {
    matches!(profile!("", ""), "retry10" | "168-full-metered")
}

// These neutral generator outputs were read on dev-samjohnson after PID1 regenerated
// them during retry10's census. Never accept a replacement of an arbitrary unit.
pub(super) fn qualified(path: &Path, digest: &str, stamp: FileStamp) -> bool {
    uses_reviewed_generators()
        && stamp.uid == 0
        && stamp.gid == 0
        && stamp.links == 1
        && stamp.mode & 0o022 == 0
        && path.parent() == Some(Path::new(BASE))
        && matches!(
            (path.file_name().and_then(|name| name.to_str()), digest),
            (
                Some("-.mount"),
                "81b1ac579c5be43aea8e1b6765b7dd31e059d119fd813f243ea87300adf9adb1"
            ) | (
                Some("boot-efi.mount"),
                "e5b4e9d62625a703d171c46139303e18918498f57a046947de95f3b00535451f"
            ) | (
                Some("home-sol.mount"),
                "e2d38e6adc1fe977d39ec1d91e2ba052a0ab6b2cc17c35483696fd8f8984be3c"
            ) | (
                Some("srv-sftp-horizon-files.mount"),
                "674b04413f0f4c6bfb5377c130a93700ea039f68b24dba43aae4b7d8e79c14c0"
            ) | (
                Some("netplan.stamp"),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        )
}

// The original inventory read, both opens around this check, and the final selected
// definition check remain strict. Only a new stable inode with the same controlled
// metadata and verified bytes can take the place of an unselected original.
pub(super) fn check(path: &Path, original: FileStamp, digest: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let current = FileStamp::new(&metadata);
    if current == original {
        return Ok(());
    }
    ensure!(
        path.canonicalize()? == path
            && metadata.is_file()
            && current.identity.inode != original.identity.inode
            && current.uid == original.uid
            && current.gid == original.gid
            && current.links == original.links
            && current.mode == original.mode
            && current.identity.device == original.identity.device
            && current.identity.length == original.identity.length,
        "generated definition changed ownership, type, device or size: {}",
        path.display()
    );
    let bytes = read_stable_bounded(path, 4096, "replaced generated definition")?;
    current.check(path)?;
    ensure!(
        hex_lower(&Sha256::digest(bytes)) == digest,
        "regenerated definition content changed: {}",
        path.display()
    );
    Ok(())
}

// Verify the full namespace in all three generator directories across the long graph
// scan. New generator units or aliases can add consumers without touching old files.
#[derive(Eq, PartialEq)]
pub(super) struct Entry {
    device: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    contents: Contents,
}

#[derive(Eq, PartialEq)]
enum Contents {
    Directory,
    Link(PathBuf),
    File(FileStamp),
    Neutral(Vec<u8>),
}

fn directory_tree(
    root: &Path,
    owner: (u32, u32),
    entries: &mut BTreeMap<PathBuf, Entry>,
) -> Result<()> {
    let mut pending = vec![root.to_owned()];
    let mut stamps = Vec::new();
    while let Some(path) = pending.pop() {
        let md = match fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(error) if path == root && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("stat generator namespace entry {}", path.display()));
            }
        };
        ensure!(
            path != root || md.is_dir(),
            "unexpected generator root type"
        );
        ensure!(
            md.is_file() || md.is_dir() || md.is_symlink(),
            "unexpected generator entry"
        );
        ensure!(
            (md.uid(), md.gid()) == owner && (md.is_symlink() || md.mode() & 0o022 == 0),
            "unsafe generator entry"
        );
        let observed = FileStamp::new(&md);
        let contents = if md.is_symlink() {
            Contents::Link(fs::read_link(&path)?)
        } else if md.is_dir() {
            Contents::Directory
        } else if md.len() <= 4096 {
            let bytes = read_stable_bounded(&path, 4096, "generator namespace member")?;
            if qualified(&path, &hex_lower(&Sha256::digest(&bytes)), observed) {
                Contents::Neutral(bytes)
            } else {
                Contents::File(observed)
            }
        } else {
            Contents::File(observed)
        };
        if md.is_dir() {
            for item in fs::read_dir(&path)
                .with_context(|| format!("list generator directory {}", path.display()))?
            {
                pending.push(
                    item.with_context(|| format!("read generator member in {}", path.display()))?
                        .path(),
                );
                ensure!(
                    pending.len() + entries.len() < 4096,
                    "generator namespace exceeds bound"
                );
            }
        }
        stamps.push((path.clone(), observed));
        entries.insert(
            path,
            Entry {
                device: md.dev(),
                mode: md.mode(),
                uid: md.uid(),
                gid: md.gid(),
                links: md.nlink(),
                contents,
            },
        );
    }
    for (path, stamp) in stamps {
        stamp.check(&path)?;
    }
    Ok(())
}

pub(super) fn inventory() -> Result<Option<BTreeMap<PathBuf, Entry>>> {
    if !uses_reviewed_generators() {
        return Ok(None);
    }
    let mut rows = BTreeMap::new();
    for root in [
        BASE,
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
    ] {
        directory_tree(Path::new(root), (0, 0), &mut rows)?;
    }
    Ok(Some(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn root_controlled_pinned_generator_names_and_profile_only() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut stamp = FileStamp::new(&tmp.as_file().metadata().unwrap());
        stamp.uid = 0;
        stamp.gid = 0;
        let root = Path::new(BASE).join("-.mount");
        let hash = "81b1ac579c5be43aea8e1b6765b7dd31e059d119fd813f243ea87300adf9adb1";
        assert_eq!(
            qualified(&root, hash, stamp),
            matches!(
                PARK,
                "horizon-closed166-retry10-park-20261122-v1.service"
                    | "horizon-closed168-full-metered-park-20261122-v1.service"
            )
        );
        assert!(!qualified(&root, &"0".repeat(64), stamp));
        assert!(!qualified(
            &Path::new(BASE).join("changed.service"),
            hash,
            stamp
        ));
        assert!(!qualified(
            Path::new("/run/systemd/transient/-.mount"),
            hash,
            stamp
        ));
        stamp.mode |= 0o020;
        assert!(!qualified(&root, hash, stamp));
        stamp.mode &= !0o020;
        stamp.uid = 1001;
        assert!(!qualified(&root, hash, stamp));
    }

    #[test]
    fn replaced_inode_must_match_the_original_bytes_and_controlled_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("file");
        let replacement = dir.path().join("replacement");
        fs::write(&source, b"old").unwrap();
        let retained = File::open(&source).unwrap();
        let original = FileStamp::new(&retained.metadata().unwrap());
        let digest = hex_lower(&Sha256::digest(b"old"));
        fs::write(&replacement, b"old").unwrap();
        fs::rename(&replacement, &source).unwrap();
        assert!(check(&source, original, &digest).is_ok());
        assert!(original.check(&source).is_err());
        fs::write(&source, b"new").unwrap();
        assert!(check(&source, original, &digest).is_err());
        fs::write(&source, b"old").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(original.mode ^ 0o020)).unwrap();
        assert!(check(&source, original, &digest).is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(original.mode)).unwrap();
        fs::hard_link(&source, &replacement).unwrap();
        assert!(check(&source, original, &digest).is_err());
        fs::remove_file(&source).unwrap();
        symlink(&replacement, &source).unwrap();
        assert!(check(&source, original, &digest).is_err());
    }

    #[test]
    fn generator_inventory_preserves_alias_spelling_membership_and_other_regular_stamps() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let md = root.metadata().unwrap();
        let snapshot = || {
            let mut records = BTreeMap::new();
            directory_tree(root, (md.uid(), md.gid()), &mut records).unwrap();
            records
        };
        let unit = root.join("unit");
        let alias = root.join("old.wants");
        fs::write(&unit, b"").unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
        let retained = File::open(&unit).unwrap();
        symlink("unit", &alias).unwrap();
        let before = snapshot();
        fs::remove_file(&alias).unwrap();
        symlink("./unit", &alias).unwrap();
        assert!(before != snapshot());
        fs::remove_file(&alias).unwrap();
        symlink("unit", &alias).unwrap();
        assert!(before == snapshot());
        fs::write(root.join("new.service"), b"").unwrap();
        fs::set_permissions(root.join("new.service"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(before != snapshot());
        fs::remove_file(root.join("new.service")).unwrap();
        assert!(before == snapshot());
        fs::remove_file(&unit).unwrap();
        fs::write(&unit, b"").unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(before != snapshot());
        drop(retained);
    }
}
