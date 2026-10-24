//! The bounded v1.6.25 comparison never admits ordinary epoch 225 publication.
use std::path::Path;
pub(crate) const BOOTSTRAP: u64 = 97_199_617;
pub(crate) const TERMINAL_ROOT: u64 = 97_631_459;

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
        || focused != Some((BOOTSTRAP, TERMINAL_ROOT))
        || root_cohort
        || recovery_or_inherited_lease
    {
        return Err("epoch225-v1-6-25-diagnostic requires exact private focused epoch 225, snapshot 97199617 and underlying canonicalroot 97631459; ordinary replay, root cohorts, inherited leases, recovery and publication are unavailable".into());
    }
    let (ledger, output, scratch) =
        paths.ok_or("epoch 225 comparison requires private ledger/output/scratch paths")?;
    let root = ledger.parent().ok_or("missing private run root")?;
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|name| {
                name.starts_with("bounded-resource-225-")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
        || ledger != root.join("ledger")
        || output != root.join("output/epoch-225-canary.jet")
        || scratch != root.join("scratch")
    {
        return Err(
            "epoch 225 comparison paths must share an isolated bounded-resource-225 private root"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Option<(&'static Path, &'static Path, &'static Path)> {
        Some((
            Path::new("/home/ubuntu/.jetstreamer-private/bounded-resource-225-test/ledger"),
            Path::new(
                "/home/ubuntu/.jetstreamer-private/bounded-resource-225-test/output/epoch-225-canary.jet",
            ),
            Path::new("/home/ubuntu/.jetstreamer-private/bounded-resource-225-test/scratch"),
        ))
    }
    #[test]
    fn only_exact_private_focused_route() {
        assert!(
            validate_launch(
                225,
                225,
                Some((BOOTSTRAP, TERMINAL_ROOT)),
                false,
                false,
                paths()
            )
            .is_ok()
        );
        for focused in [
            None,
            Some((BOOTSTRAP - 1, TERMINAL_ROOT)),
            Some((BOOTSTRAP, TERMINAL_ROOT - 1)),
            Some((BOOTSTRAP, 97_202_500)),
        ] {
            assert!(validate_launch(225, 225, focused, false, false, paths()).is_err());
        }
        for (first, last) in [(224, 224), (225, 226), (224, 225)] {
            assert!(
                validate_launch(
                    first,
                    last,
                    Some((BOOTSTRAP, TERMINAL_ROOT)),
                    false,
                    false,
                    paths()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn rejects_root_cohort_and_every_recovery_route() {
        let focused = Some((BOOTSTRAP, TERMINAL_ROOT));
        assert!(validate_launch(225, 225, focused, true, false, paths()).is_err());
        assert!(validate_launch(225, 225, focused, false, true, paths()).is_err());
    }

    #[test]
    fn rejects_public_mixed_and_absent_output_paths_before_setup() {
        let focused = Some((BOOTSTRAP, TERMINAL_ROOT));
        assert!(validate_launch(225, 225, focused, false, false, None).is_err());
        let (ledger, output, scratch) = paths().unwrap();
        for paths in [
            (Path::new("/home/ubuntu/horizon/ledger"), output, scratch),
            (
                ledger,
                Path::new("/home/ubuntu/horizon/epoch-225.jet"),
                scratch,
            ),
            (
                ledger,
                output,
                Path::new("/home/ubuntu/.jetstreamer-private/another/scratch"),
            ),
        ] {
            assert!(validate_launch(225, 225, focused, false, false, Some(paths)).is_err());
        }
    }
}
