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

pub(crate) fn validate_worker_sha(sha: [u8; 32]) -> Result<(), String> {
    const EXPECTED: [u8; 32] = [
        0xd0, 0x1a, 0xdb, 0x19, 0x80, 0xee, 0x52, 0xa5, 0x9a, 0x7a, 0xff, 0x7a, 0x3a, 0x04, 0x96,
        0x74, 0x6c, 0xa3, 0x25, 0xe5, 0xfc, 0x65, 0x58, 0x17, 0xd9, 0xa7, 0x74, 0x3a, 0x19, 0x13,
        0xef, 0x62,
    ];
    if sha == EXPECTED {
        Ok(())
    } else {
        Err("227 comparison requires its exact immutable entry-bounded v1.6.25 worker".into())
    }
}
pub(crate) fn planning_report(
    plan: crate::QualificationPlan,
    selection: &crate::compatibility::RuntimeSelection,
) -> serde_json::Value {
    let worker = selection
        .descriptor
        .worker
        .as_ref()
        .expect("227 historical profile validated");
    serde_json::json!({"schema":"jetstreamer-private-epoch227-comparison-planning-preflight-v1","epoch":227,
        "bootstrap_slot":plan.bootstrap_slot,"terminal_slot":plan.end_inclusive,"controlled_target_slot":CONTROLLED_TARGET,
        "worker_entry_start":BOOTSTRAP+1,"worker_entry_end_exclusive":CONTROLLED_TARGET+1,
        "canonical_checkpoint_slots":[BOOTSTRAP,TERMINAL_ROOT],"controlled_target_is_checkpoint":false,
        "runtime_profile":selection.descriptor.identity.name,"runtime_revision":selection.descriptor.identity.revision,
        "worker_identity":worker.identity,"worker_environment_override":worker.environment_override,
        "runtime_checkpoint_policy_validated":true,"pre_worker_barrier_reached":true,
        "worker_spawned":false,"archive_created":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
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
    fn only_the_sealed_entry_bounded_worker_can_reach_the_pre_worker_barrier() {
        let parse = |s: &str| {
            std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        };
        validate_worker_sha(parse(
            "d01adb1980ee52a59a7aff7a3a0496746ca325e5fc655817d9a7743a1913ef62",
        ))
        .unwrap();
        for other in [
            "7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a",
            "710f6523d15b960f79d91935d18d581a341e04e649df26ccd0a2b31ae9bc3eeb",
        ] {
            assert!(validate_worker_sha(parse(other)).is_err());
        }
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
