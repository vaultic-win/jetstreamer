//! Private singletons only; no ordinary compatibility-registry promotion.
#[cfg(all(
    feature = "epochs209-212-singleton-qualification",
    any(
        feature = "epoch207-singleton-qualification",
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
compile_error!("209–212 singleton qualification is an exclusive node build");
use super::singletons209_212_profile::{PROFILES, Profile, Snapshot, profile};
use std::{ops::Range, path::Path};
pub(crate) fn selected(r: &Range<u64>) -> bool {
    cfg!(feature = "epochs209-212-singleton-qualification")
        && PROFILES
            .iter()
            .any(|p| r.start > p.bootstrap.slot && r.start < r.end && r.end <= p.end())
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
    let p = profile(first)?;
    if last != first
        || verify != Some(true)
        || verifies != 1
        || !cohort
        || !candidate
        || forbidden
        || snapshot.and_then(Path::file_name).and_then(|s| s.to_str())
            != Some(p.bootstrap.filename().as_str())
    {
        return Err("private 209–212singleton requires one exact verified cohort, candidate opt-in and its cached canonical bootstrap; other modes are forbidden".into());
    }
    let root = output.parent().ok_or("singleton output root missing")?;
    if output.file_name().and_then(|s| s.to_str()) != Some("output")
        || root.parent() != Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        || !root
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with(&p.root_prefix()))
    {
        return Err("singleton output must be its own exact epoch owner-private qualification-N-singleton-*/output".into());
    }
    Ok(())
}
pub(crate) fn validate_filesystem(output: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for path in [output.parent().ok_or("singleton root missing")?, output] {
        let m =
            std::fs::symlink_metadata(path).map_err(|e| format!("precreate singleton path:{e}"))?;
        if !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || path.canonicalize().map_err(|e| e.to_string())? != path
        {
            return Err("singleton paths must be canonical current-owner0700directories".into());
        }
    }
    Ok(())
}
fn snapshot(actual: &super::CohortManifestSnapshot, expected: Snapshot) -> bool {
    actual.slot == expected.slot
        && actual.anchor_slot == expected.slot
        && actual.accounts_hash == expected.hash
        && actual.generation == expected.generation
        && actual.size == expected.size
        && actual.crc32c == expected.crc
        && actual.md5_hash == expected.md5
        && actual.source == "root"
        && actual.extension == ".tar.zst"
        && actual.uri == expected.uri()
        && actual.versioned_uri == expected.versioned_uri()
}
pub(crate) fn validate_plan(
    epoch: u64,
    plan: &super::RootCheckpointCohortPlan,
) -> Result<Profile, String> {
    let p = profile(epoch)?;
    if !snapshot(&plan.bootstrap, p.bootstrap)
        || plan.root_checkpoints.len() != 1
        || !snapshot(&plan.root_checkpoints[0], p.root)
    {
        return Err("singleton must preserve both exact generation/size/CRC/MD5 root identities with no successor checkpoint".into());
    }
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "epochs209-212-singleton-qualification")]
    #[test]
    fn four_singletons_use_the_actual_cohort_planner_and_keep_normal_registry_closed() {
        use super::super::{
            COHORT_MANIFEST_SCHEMA, COHORT_PUBLICATION_GATE, DEFAULT_BUCKET,
            cohort_manifest_fingerprint, compatibility, root_checkpoint_cohort_plan_from_report,
            root_checkpoint_cohort_runtime,
        };
        for p in PROFILES {
            assert!(compatibility::plan_runtime_spans(p.start()..p.end(), true).is_err());
            assert!(root_checkpoint_cohort_runtime(p.epoch, p.epoch, false).is_err());
            assert!(root_checkpoint_cohort_runtime(p.epoch, p.epoch + 1, true).is_err());
            let selection = root_checkpoint_cohort_runtime(p.epoch, p.epoch, true).unwrap();
            let snapshot = |s: Snapshot| {
                serde_json::json!({"slot":s.slot,"anchor_slot":s.slot,
                "accounts_hash":s.hash,"generation":s.generation,"size":s.size,"source":"root","extension":".tar.zst",
                "crc32c":s.crc,"md5_hash":s.md5,"uri":s.uri(),"versioned_uri":s.versioned_uri()})
            };
            let manifest = serde_json::json!({"schema":COHORT_MANIFEST_SCHEMA,"bucket":DEFAULT_BUCKET,"epoch_slots":432000,
                "first_epoch":p.epoch,"last_epoch":p.epoch,"verification_cohorts":[{"first_epoch":p.epoch,"last_epoch":p.epoch,
                "runtime":"solana-v1.6.16","accepted_extensions":[".tar.bz2",".tar.zst"],"publication_gate":COHORT_PUBLICATION_GATE,
                "bootstrap":snapshot(p.bootstrap),"root_checkpoints":[snapshot(p.root)]}]});
            let fp = cohort_manifest_fingerprint(&manifest).unwrap();
            let plan = root_checkpoint_cohort_plan_from_report(
                serde_json::json!({"manifest":manifest,"manifest_fingerprint":fp}),
                &fp,
                p.epoch,
                p.epoch,
                selection,
            )
            .unwrap();
            validate_plan(p.epoch, &plan).unwrap();
            for variant in 0..4 {
                let mut bad = plan.clone();
                match variant {
                    0 => bad.bootstrap.generation += 1,
                    1 => bad.root_checkpoints[0].md5_hash = serde_json::Value::Null,
                    2 => bad.root_checkpoints[0].crc32c = "AAAAAA==".into(),
                    _ => bad.root_checkpoints.push(bad.root_checkpoints[0].clone()),
                }
                assert!(validate_plan(p.epoch, &bad).is_err());
            }
        }
    }
    #[test]
    fn launch_is_a_closed_single_epoch_tuple_without_a_successor_tail() {
        for p in PROFILES {
            let out = std::path::PathBuf::from(format!(
                "/home/ubuntu/.jetstreamer-private/{}test/output",
                p.root_prefix()
            ));
            let snap = std::path::PathBuf::from(p.bootstrap.filename());
            validate_launch(
                p.epoch,
                p.epoch,
                Some(true),
                1,
                true,
                true,
                false,
                &out,
                Some(&snap),
            )
            .unwrap();
            assert_eq!(p.end() - p.start(), 432000);
            for (last, verify, forbidden) in [
                (p.epoch + 1, Some(true), false),
                (p.epoch, Some(false), false),
                (p.epoch, Some(true), true),
            ] {
                assert!(
                    validate_launch(
                        p.epoch,
                        last,
                        verify,
                        1,
                        true,
                        true,
                        forbidden,
                        &out,
                        Some(&snap)
                    )
                    .is_err()
                );
            }
            let other = PROFILES.iter().find(|o| o.epoch != p.epoch).unwrap();
            assert!(
                validate_launch(
                    p.epoch,
                    p.epoch,
                    Some(true),
                    1,
                    true,
                    true,
                    false,
                    &out,
                    Some(Path::new(&other.bootstrap.filename()))
                )
                .is_err()
            );
        }
        assert!(profile(208).is_err());
        assert!(profile(213).is_err());
        assert_eq!(
            PROFILES.map(|p| p.end() - 1 - p.root.slot),
            [361, 424, 487, 580]
        );
    }
}
