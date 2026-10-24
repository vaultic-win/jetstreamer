//! Private227 SDK comparison. The real terminal checkpoint is never fabricated.
use std::path::Path;
pub(crate) const BOOTSTRAP: u64 = 98_063_464;
pub(crate) const TERMINAL_ROOT: u64 = 98_495_291;
pub(crate) const FAILURE_SLOT: u64 = 98_091_122;
pub(crate) const CONTROLLED_TARGET: u64 = FAILURE_SLOT;
const _: () = assert!(CONTROLLED_TARGET < TERMINAL_ROOT);

pub(crate) fn validate_launch(
    first: u64,
    last: u64,
    focused: Option<(u64, u64)>,
    root_cohort: bool,
    recovery_or_inherited_lease: bool,
    paths: Option<(&Path, &Path, &Path)>,
) -> Result<(), String> {
    if first != 227
        || last != 227
        || focused != Some((BOOTSTRAP, TERMINAL_ROOT))
        || root_cohort
        || recovery_or_inherited_lease
    {
        return Err("epoch227-v1-6-25-diagnostic requires exact private focused227, snapshot98063464 and canonical underlying root98495291; ordinary replay, root cohorts, recovery and inherited leases are unavailable".into());
    }
    let (ledger, output, scratch) =
        paths.ok_or("227 comparison needs private ledger/output/scratch")?;
    let root = ledger
        .parent()
        .ok_or("227 comparison private root missing")?;
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|name| {
                name.starts_with("bounded-resource-227-v1625-")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
        || ledger != root.join("ledger")
        || output != root.join("output/epoch-227-canary.jet")
        || scratch != root.join("scratch")
    {
        return Err(
            "227 comparison paths must share an isolated bounded-resource-227-v1625 private root"
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
            Path::new("/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-test/ledger"),
            Path::new(
                "/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-test/output/epoch-227-canary.jet",
            ),
            Path::new("/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-test/scratch"),
        ))
    }
    #[test]
    fn exact_underlying_checkpoint_and_private_paths_are_required() {
        let plan = Some((BOOTSTRAP, TERMINAL_ROOT));
        assert!(validate_launch(227, 227, plan, false, false, paths()).is_ok());
        for focused in [
            None,
            Some((BOOTSTRAP - 1, TERMINAL_ROOT)),
            Some((BOOTSTRAP, FAILURE_SLOT)),
            Some((BOOTSTRAP, CONTROLLED_TARGET)),
            Some((BOOTSTRAP, TERMINAL_ROOT - 1)),
        ] {
            assert!(validate_launch(227, 227, focused, false, false, paths()).is_err());
        }
        for (first, last) in [(226, 226), (227, 228), (226, 227)] {
            assert!(validate_launch(first, last, plan, false, false, paths()).is_err());
        }
        assert!(validate_launch(227, 227, plan, true, false, paths()).is_err());
        assert!(validate_launch(227, 227, plan, false, true, paths()).is_err());
        assert!(validate_launch(227, 227, plan, false, false, None).is_err());
        let (ledger, output, scratch) = paths().unwrap();
        for p in [
            (Path::new("/home/ubuntu/horizon/ledger"), output, scratch),
            (
                ledger,
                Path::new("/home/ubuntu/horizon/epoch-227.jet"),
                scratch,
            ),
            (
                ledger,
                output,
                Path::new("/home/ubuntu/.jetstreamer-private/other/scratch"),
            ),
            (
                Path::new("/home/ubuntu/.jetstreamer-private/bounded-resource-225-test/ledger"),
                output,
                scratch,
            ),
        ] {
            assert!(validate_launch(227, 227, plan, false, false, Some(p)).is_err());
        }
    }
}
