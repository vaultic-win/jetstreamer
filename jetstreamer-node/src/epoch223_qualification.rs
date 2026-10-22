//! Private v1.6.25 epoch223 comparison. Never an ordinary runtime promotion.
use std::path::Path;

pub(crate) const COLD_BOOTSTRAP: u64 = 96_335_538;
pub(crate) const TAIL_BOOTSTRAP: u64 = 96_767_522;
pub(crate) const OUTPUT_END: u64 = 96_767_999;

pub(crate) fn validate_filesystem(ledger: &Path) -> Result<(), String> {
    // Reuse only the generic canonical-directory checks, never epoch225 policy.
    crate::epoch225_qualification::validate_filesystem(ledger)?;
    let root = ledger
        .parent()
        .ok_or("missing private qualification root")?;
    for name in ["epoch-223.jet", "epoch-223.jet.sha256"] {
        let path = root.join("output").join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err("epoch223 candidate requires fresh absent output and sidecar; preserve the existing generation".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(format!("epoch223 output identity: {e}")),
        }
    }
    Ok(())
}

/// Run before dispatching any early maintenance/recovery subcommand. The
/// focused validator below still owns all parsed epoch/path/span checks.
pub(crate) fn validate_entrypoint(args: &[String]) -> Result<(), String> {
    if !matches!(args.first().map(String::as_str), Some("223" | "223-223")) {
        return Err("epoch223 private build accepts only focused epoch223; maintenance/recovery entrypoints are disabled".into());
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
    if first != 223
        || last != 223
        || !matches!(focused, Some((COLD_BOOTSTRAP | TAIL_BOOTSTRAP, OUTPUT_END)))
        || root_cohort
        || recovery_or_inherited_lease
    {
        return Err("epoch223-v1-6-25-qualification requires private focused epoch223, exact96335538 or96767522 bootstrap and96767999 terminal; no ordinary replay, cohorts, recovery, inherited leases or publication".into());
    }
    let (ledger, output, scratch) =
        paths.ok_or("epoch223 qualification requires explicit private paths")?;
    let root = ledger
        .parent()
        .ok_or("missing private qualification root")?;
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
            s.starts_with("qualification-223-v1625-")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
        || ledger != root.join("ledger")
        || output != root.join("output/epoch-223.jet")
        || scratch != root.join("scratch")
    {
        return Err(
            "epoch223 paths require one isolated qualification-223-v1625 private root".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn paths() -> Option<(&'static Path, &'static Path, &'static Path)> {
        Some((
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-test/ledger"),
            Path::new(
                "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-test/output/epoch-223.jet",
            ),
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-test/scratch"),
        ))
    }
    #[test]
    fn fresh_output_guard_rejects_existing_archives_sidecars_and_aliases() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("private");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.join("output")).unwrap();
        let ledger = root.join("ledger");
        validate_filesystem(&ledger).unwrap();
        let archive = root.join("output/epoch-223.jet");
        std::os::unix::fs::symlink(parent.path().join("absent"), &archive).unwrap();
        assert!(validate_filesystem(&ledger).is_err());
        std::fs::remove_file(&archive).unwrap();
        std::fs::write(&archive, b"preserve").unwrap();
        assert!(validate_filesystem(&ledger).is_err());
        std::fs::remove_file(&archive).unwrap();
        std::fs::write(root.join("output/epoch-223.jet.sha256"), b"preserve").unwrap();
        assert!(validate_filesystem(&ledger).is_err());
    }
    #[test]
    fn rejects_early_recovery_dispatch_before_it_can_touch_artifacts() {
        for first in [
            "--failed-prefix220-recover",
            "--failed-prefix220-recovery-preflight",
            "--failed-prefix220-artifact-probe=220",
            "--failed-prefix220-checkpoint-probe",
            "--post-update-capacity-probe",
            "224",
            "223-224",
        ] {
            assert!(validate_entrypoint(&[first.to_string()]).is_err());
        }
        assert!(validate_entrypoint(&[]).is_err());
        for first in ["223", "223-223"] {
            assert!(validate_entrypoint(&[first.to_string()]).is_ok());
        }
    }
    #[test]
    fn exact_cold_or_tail_comparison_is_private_and_bounded() {
        for bootstrap in [COLD_BOOTSTRAP, TAIL_BOOTSTRAP] {
            let focused = Some((bootstrap, OUTPUT_END));
            assert!(validate_launch(223, 223, focused, false, false, paths()).is_ok());
            assert!(validate_launch(223, 223, focused, true, false, paths()).is_err());
            assert!(validate_launch(223, 223, focused, false, true, paths()).is_err());
            assert!(validate_launch(223, 223, focused, false, false, None).is_err());
            for (first, last) in [(222, 222), (224, 224), (223, 224)] {
                assert!(validate_launch(first, last, focused, false, false, paths()).is_err());
            }
            let (ledger, _, scratch) = paths().unwrap();
            assert!(
                validate_launch(
                    223,
                    223,
                    focused,
                    false,
                    false,
                    Some((
                        ledger,
                        Path::new("/home/ubuntu/horizon/epoch-223.jet"),
                        scratch
                    ))
                )
                .is_err()
            );
        }
        for focused in [
            None,
            Some((COLD_BOOTSTRAP - 1, OUTPUT_END)),
            Some((TAIL_BOOTSTRAP + 1, OUTPUT_END)),
            Some((COLD_BOOTSTRAP, OUTPUT_END - 1)),
            Some((TAIL_BOOTSTRAP, OUTPUT_END + 1)),
        ] {
            assert!(validate_launch(223, 223, focused, false, false, paths()).is_err());
        }
        assert_eq!(OUTPUT_END - TAIL_BOOTSTRAP, 477);
        assert_eq!(OUTPUT_END - 96_336_000 + 1, 432_000);
    }
}
