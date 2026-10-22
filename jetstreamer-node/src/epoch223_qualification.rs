//! Private v1.6.25 epoch223 comparison. Never an ordinary runtime promotion.
use crate::{BankHashExpectation, QualificationPlan, compatibility, snapshot_path_expectation};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) const COLD_BOOTSTRAP: u64 = 96_335_538;
pub(crate) const TAIL_BOOTSTRAP: u64 = 96_767_522;
pub(crate) const OUTPUT_END: u64 = 96_767_999;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TailMode {
    Disabled,
    Comparison,
    PlanningPreflight,
}

pub(crate) fn planning_report(
    plan: QualificationPlan,
    selection: &compatibility::RuntimeSelection,
) -> serde_json::Value {
    let worker = selection
        .descriptor
        .worker
        .as_ref()
        .expect("tail runtime validated");
    serde_json::json!({
        "schema":"jetstreamer-private-epoch223-tail-planning-preflight-v2",
        "epoch":223,"bootstrap_slot":plan.bootstrap_slot,"output_slot_start":plan.output_slot_start,
        "terminal_slot":plan.end_inclusive,"output_slot_count":477,
        "runtime_profile":selection.descriptor.identity.name,
        "runtime_revision":selection.descriptor.identity.revision,
        "worker_identity":worker.identity,"worker_environment_override":worker.environment_override,
        "canonical_bootstrap_bound":true,"canonical_terminal_required":false,
        "runtime_checkpoint_policy_validated":true,"pre_worker_barrier_reached":true,
        "terminal_canonical_root_independently_known":false,"tail_comparison_only":true,
        "complete_epoch_span_covered":false,"worker_spawned":false,"archive_created":false,
        "snapshot_schema_or_contents_tested":false,"fresh_resource_admission_passed":false,
        "canonical_prefix_qualified":false,"full_cold_epoch_peak_qualified":false,
        "replay_launch_authorized":false,"runtime_promotion_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false
    })
}

pub(crate) fn validate_preflight_io(
    preflight: bool,
    extract_to_ledger: bool,
    ledger: &Path,
) -> Result<(), String> {
    if preflight
        && (extract_to_ledger
            || !std::fs::symlink_metadata(ledger.join("genesis.tar.bz2"))
                .is_ok_and(|m| m.is_file()))
    {
        return Err("tail preflight requires preseeded regular genesis and forbids ledger extraction; no downloads or replay".into());
    }
    Ok(())
}

pub(crate) fn validate_tail_mode(
    enabled: bool,
    preflight: bool,
    focused: Option<(u64, u64)>,
    ledger: &Path,
) -> Result<(), String> {
    if preflight && !enabled {
        return Err("epoch223 tail preflight requires explicit tail comparison".into());
    }
    if !enabled {
        return Ok(());
    }
    if focused != Some((TAIL_BOOTSTRAP, OUTPUT_END))
        || !ledger
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("qualification-223-v1625-tail-"))
            .is_some_and(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    {
        return Err("epoch223 tail comparison accepts only its exact477-slot tail and private tail namespace; never a cold qualification".into());
    }
    Ok(())
}

pub(crate) fn validate_tail_runtime(
    selection: &compatibility::RuntimeSelection,
) -> Result<(), String> {
    let d = selection.descriptor;
    if d.identity.name != "solana-v1.6.25"
        || d.identity.revision != "7de8a55b54d3e11058b82f9483bb405d143b455c"
        || selection.admission != compatibility::AdmissionLevel::Candidate
        || !d.worker.as_ref().is_some_and(|w| {
            w.identity == "jetstreamer-historical-worker-v1-6-25"
                && w.environment_override == "JETSTREAMER_HISTORICAL_WORKER_V1_6_25"
        })
    {
        return Err(
            "epoch223 tail comparison requires exact v1.6.25 candidate descriptor and worker"
                .into(),
        );
    }
    Ok(())
}

/// This is not checkpoint qualification. The only expectation is its known
/// bootstrap; no fabricated terminal hash may be supplied to make it pass.
pub(crate) fn tail_expectations(
    mut expected: BTreeMap<u64, BankHashExpectation>,
    plan: QualificationPlan,
    snapshot: &Path,
    bootstrap: compatibility::BootstrapState,
) -> Result<BTreeMap<u64, BankHashExpectation>, String> {
    if plan.epoch != 223
        || plan.bootstrap_slot != TAIL_BOOTSTRAP
        || plan.replay_start != TAIL_BOOTSTRAP + 1
        || plan.output_slot_start != TAIL_BOOTSTRAP + 1
        || plan.end_inclusive != OUTPUT_END
    {
        return Err("tail comparison expectation scope is not exact477slots".into());
    }
    let known = BankHashExpectation::LegacyAccountsHash(
        "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
            .parse()
            .map_err(|e| format!("tail bootstrap hash: {e}"))?,
    );
    let (slot, value) = snapshot_path_expectation(snapshot, bootstrap)?;
    if slot != TAIL_BOOTSTRAP || value != known || expected.get(&slot) != Some(&known) {
        return Err("tail comparison must bind its independently known canonical bootstrap".into());
    }
    if expected
        .range(plan.replay_start..=OUTPUT_END)
        .next()
        .is_some()
    {
        return Err("tail comparison has no independently known terminal root; do not supply a fabricated post-bootstrap expectation".into());
    }
    expected.retain(|slot, _| *slot == TAIL_BOOTSTRAP);
    Ok(expected)
}

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
    async fn actual_worker_barrier(
        mode: TailMode,
        expected: Option<BTreeMap<u64, BankHashExpectation>>,
    ) -> Result<crate::ReplayRunOutcome, String> {
        use crate::{ReplayBootstrap, ReplayCursor, RestartTracker, SnapshotVerifier};
        use std::sync::{Arc, atomic::AtomicBool};
        let root = std::path::PathBuf::from(format!(
            "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-barrier-test-{}",
            std::process::id()
        ));
        assert!(!root.exists(), "planning test must use absent paths");
        let shutdown = Arc::new(AtomicBool::new(false));
        let result = crate::run_geyser_replay(
            223, true, &root.join("ledger"), &root.join("scratch"),
            &ReplayBootstrap::SnapshotArchive(Path::new("/absent/snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst").into()),
            shutdown.clone(), Arc::new(ReplayCursor::new()), Arc::new(RestartTracker::new()),
            expected.map(|e| Arc::new(SnapshotVerifier::new(e, Some(shutdown)))),
            root.join("output/epoch-223.jet"), Some(tail_plan()),
            None, None, None, None, None, None, false, None, mode,
        ).await;
        assert!(
            !root.exists(),
            "planning must not create worker/archive state"
        );
        result
    }
    #[tokio::test]
    #[cfg(feature = "epoch223-v1-6-25-qualification")]
    async fn actual_replay_barrier_preflight_covers_candidate_checkpoint_gate_without_worker() {
        let known = BankHashExpectation::LegacyAccountsHash(
            "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
                .parse()
                .unwrap(),
        );
        let expected = BTreeMap::from([(TAIL_BOOTSTRAP, known)]);
        let outcome = actual_worker_barrier(TailMode::PlanningPreflight, Some(expected.clone()))
            .await
            .unwrap();
        let crate::ReplayRunOutcome::PlanningPreflight(report) = outcome else {
            panic!("preflight cannot be replay completion");
        };
        assert_eq!(
            report["schema"],
            "jetstreamer-private-epoch223-tail-planning-preflight-v2"
        );
        assert_eq!(report["runtime_checkpoint_policy_validated"], true);
        assert_eq!(report["pre_worker_barrier_reached"], true);
        assert_eq!(report["worker_profile_validated"], true);
        assert!(
            report["worker_executable"]
                .as_str()
                .unwrap()
                .ends_with("jetstreamer-historical-worker-v1-6-25")
        );
        assert_eq!(report["worker_spawned"], false);
        assert!(
            crate::ReplayRunOutcome::PlanningPreflight(report)
                .completed()
                .is_err()
        );
        let ordinary = actual_worker_barrier(TailMode::Disabled, Some(expected.clone())).await;
        assert!(
            matches!(ordinary, Err(e) if e.contains("at least one trusted post-bootstrap checkpoint"))
        );
        assert!(
            actual_worker_barrier(TailMode::PlanningPreflight, None)
                .await
                .is_err()
        );
        assert!(
            actual_worker_barrier(TailMode::PlanningPreflight, Some(BTreeMap::new()))
                .await
                .is_err()
        );
        let mut fabricated = expected;
        fabricated.insert(COLD_BOOTSTRAP, known);
        assert!(
            actual_worker_barrier(TailMode::PlanningPreflight, Some(fabricated.clone()))
                .await
                .is_err()
        );
        fabricated.remove(&COLD_BOOTSTRAP);
        fabricated.insert(OUTPUT_END, known);
        assert!(
            actual_worker_barrier(TailMode::PlanningPreflight, Some(fabricated))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    #[cfg(not(feature = "epoch223-v1-6-25-qualification"))]
    async fn actual_default_replay_barrier_rejects_private_tail_mode_without_worker() {
        assert!(
            matches!(actual_worker_barrier(TailMode::PlanningPreflight, None).await,
            Err(e) if e.contains("explicit epoch223 tail execution cannot borrow ordinary"))
        );
    }
    fn tail_plan() -> QualificationPlan {
        QualificationPlan {
            epoch: 223,
            bootstrap_slot: TAIL_BOOTSTRAP,
            replay_start: TAIL_BOOTSTRAP + 1,
            output_slot_start: TAIL_BOOTSTRAP + 1,
            end_inclusive: OUTPUT_END,
        }
    }
    #[test]
    fn preflight_cannot_download_genesis_or_extract_accounts() {
        let t = tempfile::tempdir().unwrap();
        assert!(validate_preflight_io(true, false, t.path()).is_err());
        std::fs::write(
            t.path().join("genesis.tar.bz2"),
            b"identity-only; not snapshot proof",
        )
        .unwrap();
        validate_preflight_io(true, false, t.path()).unwrap();
        assert!(validate_preflight_io(true, true, t.path()).is_err());
        std::fs::remove_file(t.path().join("genesis.tar.bz2")).unwrap();
        std::os::unix::fs::symlink("absent", t.path().join("genesis.tar.bz2")).unwrap();
        assert!(validate_preflight_io(true, false, t.path()).is_err());
    }
    #[test]
    fn explicit_comparison_does_not_relax_normal_or_cold_terminal_qualification() {
        let ledger =
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-test/ledger");
        validate_tail_mode(true, true, Some((TAIL_BOOTSTRAP, OUTPUT_END)), ledger).unwrap();
        assert!(
            validate_tail_mode(false, true, Some((TAIL_BOOTSTRAP, OUTPUT_END)), ledger).is_err()
        );
        assert!(
            validate_tail_mode(true, false, Some((COLD_BOOTSTRAP, OUTPUT_END)), ledger).is_err()
        );
        assert!(
            validate_tail_mode(
                true,
                false,
                Some((TAIL_BOOTSTRAP, OUTPUT_END)),
                Path::new("/private/ledger")
            )
            .is_err()
        );
        let bootstrap = compatibility::SOLANA_V1_6_20_RUNTIME.bootstrap;
        let snapshot = Path::new(
            "/private/snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst",
        );
        let (_, known) = snapshot_path_expectation(snapshot, bootstrap).unwrap();
        let expected = BTreeMap::from([(TAIL_BOOTSTRAP, known)]);
        assert!(
            crate::qualification_expectations(expected.clone(), tail_plan(), snapshot, bootstrap)
                .unwrap_err()
                .contains("exact canonical terminal checkpoint")
        );
        assert_eq!(
            tail_expectations(expected, tail_plan(), snapshot, bootstrap)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn comparison_rejects_invented_terminal_hash_or_unbound_bootstrap() {
        let bootstrap = compatibility::SOLANA_V1_6_20_RUNTIME.bootstrap;
        let snapshot = Path::new(
            "/private/snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst",
        );
        let (_, known) = snapshot_path_expectation(snapshot, bootstrap).unwrap();
        let invented = BTreeMap::from([(TAIL_BOOTSTRAP, known), (OUTPUT_END, known)]);
        assert!(tail_expectations(invented, tail_plan(), snapshot, bootstrap).is_err());
        assert!(tail_expectations(BTreeMap::new(), tail_plan(), snapshot, bootstrap).is_err());
        let mut cold = tail_plan();
        cold.bootstrap_slot = COLD_BOOTSTRAP;
        assert!(
            tail_expectations(
                BTreeMap::from([(TAIL_BOOTSTRAP, known)]),
                cold,
                snapshot,
                bootstrap
            )
            .is_err()
        );
    }
    #[test]
    #[cfg(feature = "epoch223-v1-6-25-qualification")]
    fn actual_bootstrap_selector_uses_v1625_despite_static_era_label() {
        let range = crate::runtime_slot_range(223, Some(tail_plan()));
        let selected = crate::bootstrap_runtime_selection(range.clone(), true, true).unwrap();
        validate_tail_runtime(&selected).unwrap();
        assert_eq!(selected.descriptor.identity.name, "solana-v1.6.25");
        let profile = crate::historical_worker_profile(selected.descriptor).unwrap();
        assert_eq!(profile.backend_id, "solana-v1.6.25");
        assert_eq!(
            profile.solana_commit,
            "7de8a55b54d3e11058b82f9483bb405d143b455c"
        );
        let spans = crate::plan_runtime_spans_for_invocation(range, true, true).unwrap();
        assert_eq!(spans.len(), 1);
        assert!(std::ptr::eq(
            crate::runtime_span_selection(&spans[0]).unwrap().descriptor,
            selected.descriptor
        ));
    }
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
