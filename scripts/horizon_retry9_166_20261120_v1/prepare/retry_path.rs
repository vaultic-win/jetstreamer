//! Exact disjoint fresh retry mapping; never consumes the failed local3 tree.
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
fn selected(epoch: u64, attempt: &str) -> bool {
    [166, 167, 169, 170].contains(&epoch) && attempt == "local3"
}
pub(super) fn fresh_subtree(epoch: u64, attempt: &str, lane: &str) -> Result<PathBuf> {
    if selected(epoch, attempt) {
        ensure!(
            lane == format!(
                "/home/sol/.jetstreamer-private/epoch{epoch}-standard-lane-20261109-v1"
            ),
            "retry cannot change original lane"
        );
        Ok(Path::new(lane).join("replacement-local3-retry1-20261112-v1"))
    } else {
        Ok(Path::new(lane).join(format!("replacement-{attempt}-20261110-v1")))
    }
}
pub(super) fn require_fresh_start(epoch: u64, attempt: &str, existing: bool) -> Result<()> {
    ensure!(
        !(selected(epoch, attempt)
            || ([166, 167, 169, 170].contains(&epoch)
                && ["local3retry3", "local3retry4"].contains(&attempt))
            || (epoch == 166
                && ["local3retry5", "local3retry6", "local3retry7", "local3retry9"].contains(&attempt)))
            || !existing,
        "selected local3 retry requires a new empty subtree, not staged/in-place reuse"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_four_retry_roots_are_disjoint() {
        for e in [166, 167, 169, 170] {
            let lane = format!("/home/sol/.jetstreamer-private/epoch{e}-standard-lane-20261109-v1");
            let new = fresh_subtree(e, "local3", &lane).unwrap();
            assert_eq!(
                new,
                Path::new(&lane).join("replacement-local3-retry1-20261112-v1")
            );
            assert_ne!(new, Path::new(&lane).join("replacement-local3-20261110-v1"));
            assert!(require_fresh_start(e, "local3", false).is_ok());
            assert!(require_fresh_start(e, "local3", true).is_err());
        }
    }
    #[test]
    fn original_lane_cannot_change() {
        assert!(fresh_subtree(166, "local3", "/tmp/elsewhere").is_err());
        assert!(
            fresh_subtree(
                166,
                "local3",
                "/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1"
            )
            .is_err()
        );
    }
    #[test]
    fn unselected_and_older_attempts_keep_predecessor_mapping() {
        for (e, a) in [
            (166, "local2"),
            (166, "a1"),
            (168, "local3"),
            (171, "local3"),
            (170, "local30"),
        ] {
            let lane = "/retained/exact/lane";
            assert_eq!(
                fresh_subtree(e, a, lane).unwrap(),
                Path::new(lane).join(format!("replacement-{a}-20261110-v1"))
            );
            assert!(require_fresh_start(e, a, true).is_ok());
        }
    }
}
