//! Launch boundary for the explicitly built private v1.6.25 qualification.

pub(crate) const BOOTSTRAP_SLOT: u64 = 96_767_522;
// The last epoch-224 root precedes its canonical end by 382 slots. Use the
// first retained compatible later root, and keep the epoch-225 suffix private.
pub(crate) const OUTPUT_END_SLOT: u64 = 97_631_459;

/// This build can produce only a focused, complete epoch-224 diagnostic plus
/// its bounded private verification suffix through the first later root.
/// The ordinary focused path independently requires explicit verification,
/// snapshot/checkpoint files, and an output path, and writes no canonical sidecar.
pub(crate) fn validate_launch(
    first_epoch: u64,
    last_epoch: u64,
    qualification: Option<(u64, u64)>,
    root_checkpoint_cohort: bool,
    recovery_requested: bool,
) -> Result<(), String> {
    if first_epoch != 224
        || last_epoch != 224
        || qualification != Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT))
        || root_checkpoint_cohort
        || recovery_requested
    {
        return Err(format!(
            "the epoch224-v1-6-25-qualification build requires private focused epoch 224 \
             from snapshot {BOOTSTRAP_SLOT} through {OUTPUT_END_SLOT}; \
             ordinary replay, root cohorts, recovery, and publication are unavailable"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_the_exact_complete_focused_span() {
        assert!(
            validate_launch(
                224,
                224,
                Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT)),
                false,
                false
            )
            .is_ok()
        );
        for (first, last) in [(223, 224), (224, 225), (223, 223), (225, 225)] {
            assert!(
                validate_launch(
                    first,
                    last,
                    Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT)),
                    false,
                    false
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_ordinary_replay_partial_spans_and_wrong_bootstraps() {
        assert!(validate_launch(224, 224, None, false, false).is_err());
        for bootstrap in [BOOTSTRAP_SLOT - 1, BOOTSTRAP_SLOT + 1] {
            assert!(
                validate_launch(224, 224, Some((bootstrap, OUTPUT_END_SLOT)), false, false)
                    .is_err()
            );
        }
        for end in [OUTPUT_END_SLOT - 1, OUTPUT_END_SLOT + 1] {
            assert!(validate_launch(224, 224, Some((BOOTSTRAP_SLOT, end)), false, false).is_err());
        }
    }

    #[test]
    fn rejects_root_cohorts_and_every_recovery_path() {
        let focused = Some((BOOTSTRAP_SLOT, OUTPUT_END_SLOT));
        assert!(validate_launch(224, 224, focused, true, false).is_err());
        assert!(validate_launch(224, 224, focused, false, true).is_err());
    }

    #[test]
    fn terminal_is_the_exact_later_root_not_an_unchecked_epoch_end() {
        const { assert!(OUTPUT_END_SLOT > 97_199_999) };
        const { assert!(OUTPUT_END_SLOT < 97_632_000) };
        assert!(
            validate_launch(224, 224, Some((BOOTSTRAP_SLOT, 97_199_617)), false, false).is_err()
        );
        assert!(
            validate_launch(224, 224, Some((BOOTSTRAP_SLOT, 97_199_999)), false, false).is_err()
        );
    }
}
