//! Launch boundary for the explicitly built private v1.6.25 qualification.

#[cfg(all(test, feature = "epoch224-v1-6-25-qualification"))]
mod rooted_tests;

pub(crate) const BOOTSTRAP_SLOT: u64 = 96_767_522;
// The last epoch-224 root precedes its canonical end by 382 slots. Use the
// first retained compatible later root, and keep the epoch-225 suffix private.
pub(crate) const OUTPUT_END_SLOT: u64 = 97_631_459;

#[cfg(feature = "epoch224-v1-6-25-qualification")]
pub(super) const MANIFEST_SHA256: &str =
    "d4e254507eff0ff578d0569196db1e563277bdfd87994d034743dae374a829de";

#[cfg(feature = "epoch224-v1-6-25-qualification")]
pub(super) fn require_rooted_manifest() -> Result<(), String> {
    use std::{env, ffi::OsStr};

    const MANIFEST: &str =
        "/var/lib/jetstreamer/horizon224-225-rooted-ranges-v1/slot-ranges-overrides.json";
    if env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").as_deref()
        != Some(OsStr::new(MANIFEST))
        || env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            != Ok(MANIFEST_SHA256)
    {
        return Err(format!(
            "epoch 224 complete-span replay requires {MANIFEST} with SHA-256 {MANIFEST_SHA256}"
        ));
    }
    Ok(())
}

#[cfg(feature = "epoch224-v1-6-25-qualification")]
pub(super) async fn verify_rooted_tables() -> Result<(), String> {
    for epoch in [224, 225] {
        super::epoch199200_presence::RootedSlotPresence::configured(epoch)
            .await?
            .ok_or_else(|| format!("missing authenticated slot ranges for epoch {epoch}"))?;
    }
    Ok(())
}

#[cfg(feature = "epoch224-v1-6-25-qualification")]
pub(super) fn verify_warmup_compact(bytes: &[u8]) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    if format!("{:x}", Sha256::digest(bytes))
        != "a9e806d7ba3377699d6027ecc12befe9a2bb5eebe90522a9ad3f61403d8a2fc6"
    {
        return Err("epoch 223 warmup slot-to-CID table differs from the qualified census".into());
    }
    Ok(())
}

#[cfg(feature = "epoch224-v1-6-25-qualification")]
pub(super) fn verify_checkpoints(
    expected: &std::collections::BTreeMap<u64, super::BankHashExpectation>,
) -> Result<(), String> {
    for (slot, accounts) in [
        (
            BOOTSTRAP_SLOT,
            "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
        ),
        (97_199_617, "HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi"),
        (
            OUTPUT_END_SLOT,
            "EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d",
        ),
    ] {
        let hash = accounts
            .parse()
            .map_err(|_| "invalid registered epoch 224 accounts hash")?;
        if expected.get(&slot) != Some(&super::BankHashExpectation::LegacyAccountsHash(hash)) {
            return Err(format!(
                "epoch 224 complete-span replay requires the registered accounts hash at {slot}"
            ));
        }
    }
    Ok(())
}

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
