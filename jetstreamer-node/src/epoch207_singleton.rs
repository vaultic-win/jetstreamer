//! An exclusive private207cohort. No ordinary registry promotion or208tail.
#[cfg(all(
    feature = "epoch207-singleton-qualification",
    any(
        feature = "epoch141-original-entry-qualification",
        feature = "epoch140-native-restore-diagnostic",
        feature = "epoch144-native-restore-diagnostic",
        feature = "epoch203-native-restore-diagnostic",
        feature = "epoch205-native-restore-diagnostic",
        feature = "epoch213-checkpoint-continuation-diagnostic",
        feature = "epoch144-checkpoint-continuation-diagnostic",
        feature = "epoch203-checkpoint-continuation-diagnostic",
        feature = "epoch223-v1-6-25-qualification",
        feature = "epoch223-v1-6-20-prefix-qualification",
        feature = "epoch224-account-delta-diagnostic",
        feature = "epoch224-v1-6-25-diagnostic",
        feature = "epoch224-v1-6-25-qualification",
        feature = "epoch225-v1-6-25-diagnostic",
        feature = "epoch225-v1-6-25-qualification"
    )
))]
compile_error!("epoch207 singleton qualification is an exclusive node build");
use std::{ops::Range, path::Path};

pub(crate) const BOOTSTRAP: u64 = 89_423_444;
pub(crate) const START: u64 = 89_424_000;
pub(crate) const END: u64 = 89_856_000;
pub(crate) const ROOTS: [(u64, &str); 2] = [
    (89_523_820, "7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik"),
    (89_855_469, "9i59TwLmzXvbomizFZNuXgPygtx8zJ3P4nWDQuNxrTxK"),
];
pub(crate) const SNAPSHOT: &str =
    "snapshot-89423444-3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px.tar.zst";
pub(crate) fn selected(range: &Range<u64>) -> bool {
    cfg!(feature = "epoch207-singleton-qualification")
        && range.start > BOOTSTRAP
        && range.start < range.end
        && range.end <= END
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_launch(
    first: u64,
    last: u64,
    verify: Option<bool>,
    verifies: usize,
    cohort: bool,
    candidate: bool,
    forbidden: bool,
    output: &Path,
    snapshot: Option<&Path>,
) -> Result<(), String> {
    if first != 207
        || last != 207
        || verify != Some(true)
        || verifies != 1
        || !cohort
        || !candidate
        || forbidden
        || snapshot.and_then(Path::file_name).and_then(|s| s.to_str()) != Some(SNAPSHOT)
    {
        return Err("epoch207 singleton requires exact private207cohort, one explicit --verify, candidate opt-in and audited89423444snapshot; recovery, other qualifications and alternate spans are unavailable".into());
    }
    let root = output.parent().ok_or("207 output root missing")?;
    if output.file_name().and_then(|s| s.to_str()) != Some("output")
        || root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("qualification-207-singleton-"))
    {
        return Err(
            "207 singleton requires its own owner-private qualification-207-singleton-*/output"
                .into(),
        );
    }
    Ok(())
}
pub(crate) fn validate_filesystem(output: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let root = output.parent().ok_or("207 output root")?;
    for path in [root, output] {
        let m = std::fs::symlink_metadata(path)
            .map_err(|e| format!("207 precreate private path: {e}"))?;
        if !m.is_dir()
            || m.mode() & 0o077 != 0
            || m.uid() != unsafe { libc::geteuid() }
            || path.canonicalize().map_err(|e| e.to_string())? != path
        {
            return Err(
                "207 singleton paths must be canonical current-owner mode0700directories".into(),
            );
        }
    }
    Ok(())
}
pub(crate) fn validate_plan(plan: &super::RootCheckpointCohortPlan) -> Result<(), String> {
    if plan.bootstrap.slot != BOOTSTRAP
        || plan.bootstrap.accounts_hash != "3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px"
        || plan.root_checkpoints.len() != ROOTS.len()
        || !plan
            .root_checkpoints
            .iter()
            .zip(ROOTS)
            .all(|(actual, (slot, hash))| {
                actual.slot >= START && actual.slot == slot && actual.accounts_hash == hash
            })
    {
        return Err("207 singleton must preserve exact bootstrap and both canonical207roots;208tail is forbidden".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_excludes_missing208and_requires_exact_private_verified_cohort() {
        let output =
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-207-singleton-test/output");
        let valid = || {
            validate_launch(
                207,
                207,
                Some(true),
                1,
                true,
                true,
                false,
                output,
                Some(Path::new(SNAPSHOT)),
            )
        };
        valid().unwrap();
        assert_eq!(END - ROOTS[1].0 - 1, 530);
        assert!(
            validate_launch(
                207,
                208,
                Some(true),
                1,
                true,
                true,
                false,
                output,
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(
            validate_launch(
                207,
                207,
                Some(true),
                1,
                false,
                true,
                false,
                output,
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(
            validate_launch(
                207,
                207,
                Some(true),
                1,
                true,
                true,
                true,
                output,
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(
            validate_launch(
                207,
                207,
                Some(false),
                1,
                true,
                true,
                false,
                output,
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(
            validate_launch(
                207,
                207,
                Some(true),
                1,
                true,
                false,
                false,
                output,
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(
            validate_launch(
                207,
                207,
                Some(true),
                1,
                true,
                true,
                false,
                Path::new("/home/ubuntu/horizon"),
                Some(Path::new(SNAPSHOT))
            )
            .is_err()
        );
        assert!(!selected(&(START..END + 1)));
        assert!(!selected(&(89_856_117..89_856_122)));
    }
}
