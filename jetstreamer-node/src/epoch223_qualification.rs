//! Private epoch 223 era comparisons. Never an ordinary runtime promotion.
use crate::{BankHashExpectation, QualificationPlan, compatibility, snapshot_path_expectation};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) const COLD_BOOTSTRAP: u64 = 96_335_538;
pub(crate) const TAIL_BOOTSTRAP: u64 = 96_767_522;
pub(crate) const OUTPUT_END: u64 = 96_767_999;

pub(crate) fn private_build_enabled() -> bool {
    cfg!(any(
        feature = "epoch223-v1-6-25-qualification",
        feature = "epoch223-v1-6-20-prefix-qualification"
    ))
}

fn private_namespace() -> &'static str {
    if cfg!(feature = "epoch223-v1-6-20-prefix-qualification") {
        "qualification-223-v1620-"
    } else {
        "qualification-223-v1625-"
    }
}

fn prefix_namespace() -> &'static str {
    if cfg!(feature = "epoch223-v1-6-20-prefix-qualification") {
        "qualification-223-v1620-prefix-"
    } else {
        "qualification-223-v1625-prefix-"
    }
}

#[cfg(all(test, feature = "epoch223-v1-6-20-prefix-qualification"))]
mod v1620_tests {
    use super::*;
    fn plan() -> QualificationPlan {
        QualificationPlan {
            epoch: 223,
            bootstrap_slot: COLD_BOOTSTRAP,
            replay_start: COLD_BOOTSTRAP + 1,
            output_slot_start: 96_336_000,
            end_inclusive: TAIL_BOOTSTRAP,
        }
    }
    fn expected() -> BTreeMap<u64, BankHashExpectation> {
        [
            (
                COLD_BOOTSTRAP,
                "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE",
            ),
            (
                TAIL_BOOTSTRAP,
                "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
            ),
        ]
        .into_iter()
        .map(|(slot, hash)| {
            (
                slot,
                BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap()),
            )
        })
        .collect()
    }
    #[test]
    fn original_runtime_prefix_is_exact_and_cannot_borrow_tail_or_v1625_paths() {
        let root =
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-test");
        let ledger = root.join("ledger");
        let output = root.join("output/epoch-223.jet");
        let scratch = root.join("scratch");
        for (focused, cohort, recovery, valid) in [
            (Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP)), false, false, true),
            (Some((COLD_BOOTSTRAP, OUTPUT_END)), false, false, false),
            (Some((TAIL_BOOTSTRAP, OUTPUT_END)), false, false, false),
            (Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP)), true, false, false),
            (Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP)), false, true, false),
        ] {
            assert_eq!(
                validate_launch(
                    223,
                    223,
                    focused,
                    cohort,
                    recovery,
                    Some((&ledger, &output, &scratch))
                )
                .is_ok(),
                valid
            );
        }
        assert!(
            validate_tail_mode(true, false, Some((TAIL_BOOTSTRAP, OUTPUT_END)), &ledger).is_err()
        );
        let wrong =
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-test");
        assert!(
            validate_launch(
                223,
                223,
                Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP)),
                false,
                false,
                Some((
                    &wrong.join("ledger"),
                    &wrong.join("output/epoch-223.jet"),
                    &wrong.join("scratch")
                ))
            )
            .is_err()
        );
        validate_prefix_expectations(&expected(), plan()).unwrap();
        for slot in [COLD_BOOTSTRAP, TAIL_BOOTSTRAP] {
            let mut incomplete = expected();
            incomplete.remove(&slot);
            assert!(validate_prefix_expectations(&incomplete, plan()).is_err());
        }
        let selection = compatibility::select_focused_qualification_runtime(
            COLD_BOOTSTRAP + 1..TAIL_BOOTSTRAP + 1,
            true,
        )
        .unwrap();
        validate_tail_runtime(&selection).unwrap();
        assert_eq!(selection.descriptor.identity.name, "solana-v1.6.20");
        assert_eq!(
            selection.descriptor.identity.revision,
            compatibility::SOLANA_V1_6_20_REVISION
        );
    }
    #[tokio::test]
    async fn original_runtime_prefix_reaches_real_worker_barrier_only_with_both_roots() {
        use crate::{ReplayBootstrap, ReplayCursor, RestartTracker, SnapshotVerifier};
        use std::sync::{Arc, atomic::AtomicBool};
        let root = std::path::PathBuf::from(format!(
            "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-barrier-test-{}",
            std::process::id()
        ));
        for missing in [None, Some(COLD_BOOTSTRAP), Some(TAIL_BOOTSTRAP)] {
            assert!(!root.exists());
            let mut checkpoints = expected();
            if let Some(slot) = missing {
                checkpoints.remove(&slot);
            }
            let shutdown = Arc::new(AtomicBool::new(false));
            let outcome=crate::run_geyser_replay(223,true,&root.join("ledger"),&root.join("scratch"),
                &ReplayBootstrap::SnapshotArchive(Path::new("/absent/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst").into()),
                shutdown.clone(),Arc::new(ReplayCursor::new()),Arc::new(RestartTracker::new()),
                Some(Arc::new(SnapshotVerifier::new(checkpoints,Some(shutdown)))),root.join("output/epoch-223.jet"),
                Some(plan()),None,None,None,None,None,None,false,None,TailMode::PrefixPlanningPreflight).await;
            assert!(!root.exists());
            if missing.is_some() {
                assert!(outcome.is_err());
                continue;
            }
            let crate::ReplayRunOutcome::PlanningPreflight(report) = outcome.unwrap() else {
                panic!("preflight cannot complete replay");
            };
            assert_eq!(report["runtime_profile"], "solana-v1.6.20");
            assert_eq!(
                report["worker_environment_override"],
                "JETSTREAMER_HISTORICAL_WORKER_V1_6_20"
            );
            assert_eq!(report["canonical_terminal_required"], true);
            assert_eq!(report["worker_profile_validated"], true);
            assert_eq!(report["runtime_checkpoint_policy_validated"], true);
            for key in [
                "worker_spawned",
                "archive_created",
                "publication_authorized",
                "r2_mutations",
            ] {
                assert_eq!(report[key], false);
            }
        }
    }
}

/// This exact private span retains the ordinary terminal-checkpoint obligation.
/// It is a prefix qualification, never an exception like the bootstrap-only tail.
pub(crate) fn is_known_root_prefix(plan: QualificationPlan) -> bool {
    plan.epoch == 223
        && plan.bootstrap_slot == COLD_BOOTSTRAP
        && plan.replay_start == COLD_BOOTSTRAP + 1
        && plan.output_slot_start == 96_336_000
        && plan.end_inclusive == TAIL_BOOTSTRAP
}

pub(crate) fn validate_prefix_expectations(
    expected: &BTreeMap<u64, BankHashExpectation>,
    plan: QualificationPlan,
) -> Result<(), String> {
    if !is_known_root_prefix(plan) {
        return Err("epoch223 prefix requires its exact cold bootstrap, epoch output start and known terminal root".into());
    }
    for (slot, hash) in [
        (
            COLD_BOOTSTRAP,
            "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE",
        ),
        (
            TAIL_BOOTSTRAP,
            "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
        ),
    ] {
        let known = BankHashExpectation::LegacyAccountsHash(
            hash.parse()
                .map_err(|e| format!("prefix checkpoint: {e}"))?,
        );
        if expected.get(&slot) != Some(&known) {
            return Err(format!(
                "epoch223 prefix requires the independently known accounts checkpoint at slot {slot}"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TailMode {
    Disabled,
    Comparison,
    PlanningPreflight,
    PrefixPlanningPreflight,
}

pub(crate) fn validate_prefix_preflight(
    enabled: bool,
    tail_comparison: bool,
    tail_preflight: bool,
    plan: Option<QualificationPlan>,
) -> Result<(), String> {
    if enabled && (tail_comparison || tail_preflight || !plan.is_some_and(is_known_root_prefix)) {
        return Err("epoch223 prefix preflight requires only the exact cold-to-known-root prefix; tail flags and full-epoch terminals are forbidden".into());
    }
    Ok(())
}

pub(crate) fn prefix_planning_report(
    plan: QualificationPlan,
    selection: &compatibility::RuntimeSelection,
) -> serde_json::Value {
    let mut report = planning_report(plan, selection);
    report["schema"] =
        serde_json::json!("jetstreamer-private-epoch223-prefix-planning-preflight-v1");
    report["output_slot_count"] = serde_json::json!(431_523);
    report["canonical_terminal_required"] = serde_json::json!(true);
    report["terminal_canonical_root_independently_known"] = serde_json::json!(true);
    report["tail_comparison_only"] = serde_json::json!(false);
    report["known_root_prefix_planning_only"] = serde_json::json!(true);
    report
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
    if cfg!(feature = "epoch223-v1-6-20-prefix-qualification") {
        return Err(
            "v1.6.20 prefix build cannot execute or preflight the incompatible tail".into(),
        );
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
        return Err("epoch 223 tail comparison accepts only its exact 477-slot tail and private tail namespace; never a cold qualification".into());
    }
    Ok(())
}

pub(crate) fn validate_tail_runtime(
    selection: &compatibility::RuntimeSelection,
) -> Result<(), String> {
    let d = selection.descriptor;
    let (name, revision, identity, environment) =
        if cfg!(feature = "epoch223-v1-6-20-prefix-qualification") {
            (
                "solana-v1.6.20",
                compatibility::SOLANA_V1_6_20_REVISION,
                "jetstreamer-historical-worker-v1-6-20",
                "JETSTREAMER_HISTORICAL_WORKER_V1_6_20",
            )
        } else {
            (
                "solana-v1.6.25",
                "7de8a55b54d3e11058b82f9483bb405d143b455c",
                "jetstreamer-historical-worker-v1-6-25",
                "JETSTREAMER_HISTORICAL_WORKER_V1_6_25",
            )
        };
    if d.identity.name != name
        || d.identity.revision != revision
        || selection.admission != compatibility::AdmissionLevel::Candidate
        || !d
            .worker
            .as_ref()
            .is_some_and(|w| w.identity == identity && w.environment_override == environment)
    {
        return Err(
            "epoch223 comparison requires its exact build-selected candidate descriptor and worker"
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
        return Err("tail comparison expectation scope is not exact 477 slots".into());
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
    // Reuse only the generic canonical-directory checks, never epoch 225 policy.
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
    if cfg!(feature = "epoch223-v1-6-20-prefix-qualification")
        && focused != Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP))
    {
        return Err("v1.6.20 prefix build accepts only the exact cold-to-known-root span".into());
    }
    if first != 223
        || last != 223
        || !matches!(
            focused,
            Some((COLD_BOOTSTRAP | TAIL_BOOTSTRAP, OUTPUT_END) | (COLD_BOOTSTRAP, TAIL_BOOTSTRAP))
        )
        || root_cohort
        || recovery_or_inherited_lease
    {
        return Err("epoch223-v1-6-25-qualification requires private focused epoch223, exact cold-to-known-root prefix or cold/tail-to96767999 span; no ordinary replay, cohorts, recovery, inherited leases or publication".into());
    }
    let (ledger, output, scratch) =
        paths.ok_or("epoch223 qualification requires explicit private paths")?;
    let root = ledger
        .parent()
        .ok_or("missing private qualification root")?;
    let is_prefix_namespace = root
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix(prefix_namespace()))
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    let prefix_reserved = root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.starts_with(prefix_namespace().trim_end_matches('-')));
    if (prefix_reserved && !is_prefix_namespace)
        || is_prefix_namespace != (focused == Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP)))
    {
        return Err("epoch223 known-root prefix requires its exclusive private prefix namespace and exact span".into());
    }
    if root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
            s.starts_with(private_namespace())
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

#[cfg(all(test, not(feature = "epoch223-v1-6-20-prefix-qualification")))]
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
    #[tokio::test]
    #[cfg(feature = "epoch223-v1-6-25-qualification")]
    async fn actual_prefix_planning_barrier_requires_both_roots_and_creates_nothing() {
        use crate::{ReplayBootstrap, ReplayCursor, RestartTracker, SnapshotVerifier};
        use std::sync::{Arc, atomic::AtomicBool};
        let root = std::path::PathBuf::from(format!(
            "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-barrier-test-{}",
            std::process::id()
        ));
        let plan = QualificationPlan {
            epoch: 223,
            bootstrap_slot: COLD_BOOTSTRAP,
            replay_start: COLD_BOOTSTRAP + 1,
            output_slot_start: 96_336_000,
            end_inclusive: TAIL_BOOTSTRAP,
        };
        let expected = BTreeMap::from([
            (
                COLD_BOOTSTRAP,
                BankHashExpectation::LegacyAccountsHash(
                    "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
                        .parse()
                        .unwrap(),
                ),
            ),
            (
                TAIL_BOOTSTRAP,
                BankHashExpectation::LegacyAccountsHash(
                    "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
                        .parse()
                        .unwrap(),
                ),
            ),
        ]);
        for missing in [None, Some(COLD_BOOTSTRAP), Some(TAIL_BOOTSTRAP)] {
            assert!(!root.exists());
            let mut checkpoints = expected.clone();
            if let Some(slot) = missing {
                checkpoints.remove(&slot);
            }
            let shutdown = Arc::new(AtomicBool::new(false));
            let outcome = crate::run_geyser_replay(
                223,true,&root.join("ledger"),&root.join("scratch"),
                &ReplayBootstrap::SnapshotArchive(Path::new("/absent/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst").into()),
                shutdown.clone(),Arc::new(ReplayCursor::new()),Arc::new(RestartTracker::new()),
                Some(Arc::new(SnapshotVerifier::new(checkpoints,Some(shutdown)))),
                root.join("output/epoch-223.jet"),Some(plan),None,None,None,None,None,None,false,None,
                TailMode::PrefixPlanningPreflight).await;
            assert!(
                !root.exists(),
                "prefix planning created worker or archive state"
            );
            if missing.is_some() {
                assert!(outcome.is_err());
                continue;
            }
            let crate::ReplayRunOutcome::PlanningPreflight(report) = outcome.unwrap() else {
                panic!("prefix preflight must never report replay completion");
            };
            assert_eq!(
                report["schema"],
                "jetstreamer-private-epoch223-prefix-planning-preflight-v1"
            );
            for key in [
                "canonical_terminal_required",
                "terminal_canonical_root_independently_known",
                "pre_worker_barrier_reached",
                "runtime_checkpoint_policy_validated",
                "worker_profile_validated",
            ] {
                assert_eq!(report[key], true, "{key}");
            }
            assert_eq!(report["output_slot_count"], 431523);
            for key in [
                "worker_spawned",
                "archive_created",
                "tail_comparison_only",
                "replay_launch_authorized",
                "canonical_sidecar_authorized",
                "publication_authorized",
                "r2_mutations",
            ] {
                assert_eq!(report[key], false, "{key}");
            }
        }
    }
    #[test]
    fn prefix_preflight_never_borrows_tail_or_full_epoch_authority() {
        let plan = QualificationPlan {
            epoch: 223,
            bootstrap_slot: COLD_BOOTSTRAP,
            replay_start: COLD_BOOTSTRAP + 1,
            output_slot_start: 96_336_000,
            end_inclusive: TAIL_BOOTSTRAP,
        };
        validate_prefix_preflight(true, false, false, Some(plan)).unwrap();
        assert!(validate_prefix_preflight(true, true, false, Some(plan)).is_err());
        assert!(validate_prefix_preflight(true, false, true, Some(plan)).is_err());
        assert!(validate_prefix_preflight(true, false, false, None).is_err());
        assert!(validate_prefix_preflight(true, false, false, Some(tail_plan())).is_err());
        let mut full = plan;
        full.end_inclusive = OUTPUT_END;
        assert!(validate_prefix_preflight(true, false, false, Some(full)).is_err());
    }
    #[test]
    fn cold_epoch_still_requires_missing_terminal_but_private_prefix_binds_known_root() {
        let bootstrap = compatibility::SOLANA_V1_6_20_RUNTIME.bootstrap;
        let snapshot = Path::new(
            "/private/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
        );
        let (_, cold_hash) = snapshot_path_expectation(snapshot, bootstrap).unwrap();
        let root_hash = BankHashExpectation::LegacyAccountsHash(
            "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
                .parse()
                .unwrap(),
        );
        let expected = BTreeMap::from([(COLD_BOOTSTRAP, cold_hash), (TAIL_BOOTSTRAP, root_hash)]);
        let mut plan = QualificationPlan {
            epoch: 223,
            bootstrap_slot: COLD_BOOTSTRAP,
            replay_start: COLD_BOOTSTRAP + 1,
            output_slot_start: 96_336_000,
            end_inclusive: OUTPUT_END,
        };
        let error = crate::qualification_expectations(expected.clone(), plan, snapshot, bootstrap)
            .unwrap_err();
        assert!(error.contains("exact canonical terminal checkpoint at slot 96767999"));
        assert!(tail_expectations(expected.clone(), plan, snapshot, bootstrap).is_err());

        // The prefix uses the existing exact terminal rules, not the tail's
        // bootstrap-only exception. Restart/assembly and admission stay separate.
        plan.end_inclusive = TAIL_BOOTSTRAP;
        let bound = crate::qualification_expectations(expected, plan, snapshot, bootstrap).unwrap();
        validate_prefix_expectations(&bound, plan).unwrap();
        if cfg!(feature = "epoch223-v1-6-25-qualification") {
            let mut invented = bound.clone();
            invented.insert(TAIL_BOOTSTRAP, cold_hash);
            assert!(
                crate::qualification_expectations(invented, plan, snapshot, bootstrap).is_err()
            );
        }
        assert_eq!(bound.len(), 2);
        assert_eq!(plan.slot_count(), 431_523);
        assert_eq!(plan.end_inclusive - plan.replay_start + 1, 431_984);
        assert_eq!(432_000 - plan.slot_count(), 477);
        for slot in [COLD_BOOTSTRAP, TAIL_BOOTSTRAP] {
            let mut missing = bound.clone();
            missing.remove(&slot);
            assert!(validate_prefix_expectations(&missing, plan).is_err());
            missing.insert(
                slot,
                if slot == COLD_BOOTSTRAP {
                    root_hash
                } else {
                    cold_hash
                },
            );
            assert!(validate_prefix_expectations(&missing, plan).is_err());
        }
        assert!(validate_prefix_expectations(&bound, tail_plan()).is_err());
    }
    #[test]
    fn prefix_namespace_cannot_borrow_tail_cold_full_or_cohort_authority() {
        let root =
            Path::new("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-prefix-test");
        let ledger = root.join("ledger");
        let output = root.join("output/epoch-223.jet");
        let scratch = root.join("scratch");
        let prefix_paths = Some((ledger.as_path(), output.as_path(), scratch.as_path()));
        let prefix = Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP));
        validate_launch(223, 223, prefix, false, false, prefix_paths).unwrap();
        for span in [
            None,
            Some((COLD_BOOTSTRAP, OUTPUT_END)),
            Some((TAIL_BOOTSTRAP, OUTPUT_END)),
            Some((COLD_BOOTSTRAP, TAIL_BOOTSTRAP - 1)),
        ] {
            assert!(validate_launch(223, 223, span, false, false, prefix_paths).is_err());
        }
        assert!(validate_launch(223, 223, prefix, false, false, paths()).is_err());
        assert!(validate_launch(223, 223, prefix, true, false, prefix_paths).is_err());
        assert!(validate_launch(223, 223, prefix, false, true, prefix_paths).is_err());
        assert!(validate_launch(223, 224, prefix, false, false, prefix_paths).is_err());
        assert!(validate_tail_mode(true, false, prefix, &ledger).is_err());
        for name in [
            "qualification-223-v1625-prefix-",
            "qualification-223-v1625-prefix-bad_name",
        ] {
            let root = root.with_file_name(name);
            let ledger = root.join("ledger");
            let output = root.join("output/epoch-223.jet");
            let scratch = root.join("scratch");
            let paths = Some((ledger.as_path(), output.as_path(), scratch.as_path()));
            assert!(validate_launch(223, 223, prefix, false, false, paths).is_err());
            assert!(
                validate_launch(
                    223,
                    223,
                    Some((COLD_BOOTSTRAP, OUTPUT_END)),
                    false,
                    false,
                    paths
                )
                .is_err()
            );
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
