//! Complete private epoch 225; the epoch 226 suffix is verification evidence only.
use std::path::Path;

pub(crate) const BOOTSTRAP_SLOT: u64 = 97_199_617;
pub(crate) const OUTPUT_END_SLOT: u64 = 98_063_464;

/// The operator must precreate the isolated root. Do not follow an alias into
/// public output even when its lexical name looks private.
pub(crate) fn validate_filesystem(ledger: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let root = ledger
        .parent()
        .ok_or("missing private qualification root")?;
    let meta =
        std::fs::symlink_metadata(root).map_err(|e| format!("private root metadata: {e}"))?;
    if !meta.is_dir()
        || meta.mode() & 0o022 != 0
        || root
            .canonicalize()
            .map_err(|e| format!("private root identity: {e}"))?
            != root
    {
        return Err(
            "precreate a canonical non-writable-by-others private qualification root".into(),
        );
    }
    for path in [
        ledger.to_path_buf(),
        root.join("output"),
        root.join("scratch"),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_dir() || path.canonicalize().map_err(|e| e.to_string())? != path {
                    return Err("qualification child directory is an alias or non-directory".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

pub(crate) fn validate_launch(
    first: u64,
    last: u64,
    focused: Option<(u64, u64)>,
    root_cohort: bool,
    recovery_or_inherited_lease: bool,
    paths: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    if first != 225
        || last != 225
        || focused != Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT))
        || root_cohort
        || recovery_or_inherited_lease
    {
        return Err("epoch225-v1-6-25-qualification requires exact private focused epoch 225 from 97199617 through 98063464; ordinary replay, cohorts, inherited leases, recovery and publication are unavailable".into());
    }
    let (ledger, output, scratch) =
        paths.ok_or("complete epoch 225 qualification requires explicit private paths")?;
    let root = ledger
        .parent()
        .ok_or("missing private qualification root")?;
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
            s.starts_with("qualification-225-v1625-")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
        || ledger != root.join("ledger")
        || output != root.join("output/epoch-225.jet")
        || scratch != root.join("scratch")
    {
        return Err("complete epoch 225 qualification paths require one isolated qualification-225-v1625 private root".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn paths() -> Option<(&'static Path, &'static Path, &'static Path)> {
        Some((
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-225-v1625-test/ledger"),
            Path::new(
                "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-test/output/epoch-225.jet",
            ),
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-225-v1625-test/scratch"),
        ))
    }
    #[test]
    fn accepts_only_exact_full_span_and_private_paths() {
        assert!(
            validate_launch(
                225,
                225,
                Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT)),
                false,
                false,
                paths()
            )
            .is_ok()
        );
        for span in [
            None,
            Some((BOOTSTRAP_SLOT - 1, OUTPUT_END_SLOT)),
            Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT - 1)),
            Some((BOOTSTRAP_SLOT, 97_631_459)),
            Some((BOOTSTRAP_SLOT, 97_631_999)),
        ] {
            assert!(validate_launch(225, 225, span, false, false, paths()).is_err());
        }
        for (first, last) in [(224, 224), (225, 226), (226, 226)] {
            assert!(
                validate_launch(
                    first,
                    last,
                    Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT)),
                    false,
                    false,
                    paths()
                )
                .is_err()
            );
        }
        let focused = Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT));
        assert!(validate_launch(225, 225, focused, true, false, paths()).is_err());
        assert!(validate_launch(225, 225, focused, false, true, paths()).is_err());
        assert!(validate_launch(225, 225, focused, false, false, None).is_err());
        let (ledger, _, scratch) = paths().unwrap();
        assert!(
            validate_launch(
                225,
                225,
                focused,
                false,
                false,
                Some((
                    ledger,
                    Path::new("/home/ubuntu/horizon/epoch-225.jet"),
                    scratch
                ))
            )
            .is_err()
        );
    }
    #[test]
    fn target_and_tail_do_not_claim_epoch226_completion() {
        const { assert!(OUTPUT_END_SLOT > 97_631_999 && OUTPUT_END_SLOT < 98_063_999) };
        assert_eq!(OUTPUT_END_SLOT - 97_200_000 + 1, 863_465);
        assert_eq!(97_631_999 - 97_631_459, 540);
    }

    #[test]
    fn rejects_symlinked_roots_and_children_before_destination_setup() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("private");
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = root.join("ledger");
        validate_filesystem(&ledger).unwrap();
        let alias = parent.path().join("alias");
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(validate_filesystem(&alias.join("ledger")).is_err());
        std::os::unix::fs::symlink(parent.path(), root.join("output")).unwrap();
        assert!(validate_filesystem(&ledger).is_err());
    }
}
