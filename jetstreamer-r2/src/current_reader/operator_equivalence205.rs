//! Exact operator-only changes reviewed against the qualified db1c31fe reader.
//! No general manifest/lockfile/path exception: every changed tree entry is pinned.
use super::*;
const BASE: &str = "db1c31fe4e6d462a8e45c18c61f6b331a9c1a1c6";
const QUALIFICATION_SHA: &str = "1a29e8abf04c8fc411eecba67525be26e27227f1f5ae8dc34b4bbacfb04eaf21";
type TreeTransition = (&'static str, &'static str, &'static str);
const CHANGES: &[TreeTransition] = &[
    (
        "Cargo.toml",
        "100644 blob 85d88dfd3df0b6bfa818b69678361d2447a4e44c\tCargo.toml",
        "100644 blob 3b0160efb9a757982ccf8d5e5cbb46a2755a3845\tCargo.toml",
    ),
    (
        "Cargo.lock",
        "100644 blob 83d1f984f9c6f3ae168a3f2cfa53f87fdb0fed0b\tCargo.lock",
        "100644 blob 3898bf26bae3c012817361684adf3626f3847f57\tCargo.lock",
    ),
    (
        "jetstreamer-utils/Cargo.toml",
        "100644 blob 0c4926515628ed2558e6b27aa4078307bae0e501\tjetstreamer-utils/Cargo.toml",
        "100644 blob a378d48316801357bb008fca398539750259fde4\tjetstreamer-utils/Cargo.toml",
    ),
    (
        "jetstreamer-utils/src/horizon_standalone_guard_bin.rs",
        "100644 blob 532e0ea3679987e0bc12d00cb9722ba603218e07\tjetstreamer-utils/src/horizon_standalone_guard_bin.rs",
        "100644 blob bc1e2c3c98d5e54a896c0a61cbccfc66901a4502\tjetstreamer-utils/src/horizon_standalone_guard_bin.rs",
    ),
    (
        "jetstreamer-utils/src/horizon_standalone_guard_native227.rs",
        "100644 blob a9de0b3ff8f45958bc3e54f12d8aeab6d57dae57\tjetstreamer-utils/src/horizon_standalone_guard_native227.rs",
        "100644 blob a2af30c4b67d60670a4ced6d61b8f41ddd3219e2\tjetstreamer-utils/src/horizon_standalone_guard_native227.rs",
    ),
    // A standalone Cargo bin target. Neither qualified reader target compiles this file.
    // git ls-tree returns an empty string for its absence in the original reader tree.
    (
        "jetstreamer-firehose/src/bin/epoch257-native-window-audit.rs",
        "",
        "100644 blob 8707032b5fd124a145779efc89c835078bb8862b\tjetstreamer-firehose/src/bin/epoch257-native-window-audit.rs",
    ),
];
// The two standalone audit bins are the only targets declaring mod native_window.
// Its mod.rs has no main.rs sibling and introduces no independent Cargo target.
const AUDIT261_COMMIT: &str = "4284526370cf555901b205dce7e36f81f5a2c0c4";
const AUDIT261: &[TreeTransition] = &[
    (
        "jetstreamer-firehose/src/bin/epoch257-native-window-audit.rs",
        "",
        "100644 blob 32a1c372ca5648a784f62cce3bd685707e639421\tjetstreamer-firehose/src/bin/epoch257-native-window-audit.rs",
    ),
    (
        "jetstreamer-firehose/src/bin/epoch261-native-window-audit.rs",
        "",
        "100644 blob d84614dc5108746f00d0d5e5cd3a7dbc7e7fcaea\tjetstreamer-firehose/src/bin/epoch261-native-window-audit.rs",
    ),
    (
        "jetstreamer-firehose/src/bin/native_window/mod.rs",
        "",
        "100644 blob 2593d41cfafd695885347437fe480311462458c6\tjetstreamer-firehose/src/bin/native_window/mod.rs",
    ),
];
fn includes_261(changed: &str) -> bool {
    changed
        .lines()
        .any(|path| AUDIT261[1..].iter().any(|(p, _, _)| *p == path))
}
fn reviewed_entries(changed: &str) -> impl Iterator<Item = &'static TreeTransition> {
    let include_261 = includes_261(changed);
    CHANGES
        .iter()
        .filter(move |(path, _, _)| !include_261 || *path != AUDIT261[0].0)
        .chain(AUDIT261.iter().filter(move |_| include_261))
}
fn exact_changes(changed: &str, mut entry: impl FnMut(bool, &str) -> Result<String>) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    ensure!(
        !changed.is_empty(),
        "reviewed transition must contain an actual change"
    );
    for path in changed.lines() {
        ensure!(seen.insert(path), "duplicate reader change");
        let (_, before, after) = reviewed_entries(changed)
            .find(|(p, _, _)| *p == path)
            .context("unreviewed reader source/dependency/build change")?;
        ensure!(
            entry(false, path)? == *before && entry(true, path)? == *after,
            "reviewed reader transition blob or mode changed: {path}"
        );
    }
    if includes_261(changed) {
        ensure!(
            AUDIT261.iter().all(|(p, _, _)| seen.contains(p)),
            "incomplete standalone audit transition"
        );
    }
    Ok(())
}
pub(super) fn validate(plan: &Plan, head: &str, changed: &str) -> Result<()> {
    ensure!(
        plan.reader_commit == BASE
            && plan.qualification.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-skipped-tail-qualified-db1c31fe-20261119-v1/main-acceptance.json"
                )
            && plan.qualification.sha256 == QUALIFICATION_SHA,
        "reviewed transition requires exact original artifact/features acceptance"
    );
    let q: Qualification = serde_json::from_value(bound_json(&plan.qualification)?)?;
    validate_qualification(plan, &q)?;
    ensure!(
        q.cargo_features
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            == ["jetstreamer/default", "jetstreamer-firehose/default"]
            && plan.pipeline.sha256
                == "310d2ba1c6bf866ce4d02773f0c778f0669d106594c4f24cac80284a39675bb8"
            && plan.full_verifier.sha256
                == "f31ada10fd7e25247176c602f72fdaecff51d2fcb95bf40a6956f4db837f1e1f",
        "reviewed reader feature/artifact set differs"
    );
    exact_changes(changed, |after, path| {
        git(
            plan,
            &[
                "ls-tree",
                if after { head } else { &plan.reader_commit },
                "--",
                path,
            ],
        )
    })
}
pub(super) fn record(changed: &str) -> Value {
    let mut receipt = json!({"schema":"horizon-reader-exact-operator-equivalence205-v1",
        "original_reader_commit":BASE,"qualification_sha256":QUALIFICATION_SHA,
        "changed_paths":changed.lines().collect::<Vec<_>>(),
        "reviewed_tree_entries":reviewed_entries(changed).filter(|(path,_,_)|changed.lines().any(|p|p==*path)).map(|(path,before,after)|
            json!({"path":path,"before":before,"after":after})).collect::<Vec<_>>(),
        "reader_dependency_or_feature_change_authorized":false});
    if includes_261(changed) {
        receipt["schema"] = json!("horizon-reader-exact-operator-equivalence261-v1");
        receipt["standalone_audit_source_commit"] = json!(AUDIT261_COMMIT);
    }
    receipt
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original_entry(after: bool, path: &str) -> Result<String> {
        let (_, a, b) = CHANGES
            .iter()
            .find(|(p, _, _)| *p == path)
            .context("fixture path")?;
        Ok(if after { *b } else { *a }.into())
    }
    #[test]
    fn accepted_transition_does_not_hide_a_relevant_reader_change() {
        let changed = CHANGES
            .iter()
            .map(|(p, _, _)| *p)
            .collect::<Vec<_>>()
            .join("\n");
        exact_changes(&changed, original_entry).unwrap();
        assert!(
            exact_changes(
                &format!("{changed}\njetstreamer-horizon/src/lib.rs"),
                original_entry
            )
            .is_err()
        );
        assert!(exact_changes("Cargo.lock\nCargo.lock", original_entry).is_err());
        assert!(exact_changes("", original_entry).is_err());
    }
    #[test]
    fn audit261_accepts_only_the_three_reviewed_entries_together() {
        let changed = CHANGES
            .iter()
            .map(|e| e.0)
            .chain(AUDIT261[1..].iter().map(|e| e.0))
            .collect::<Vec<_>>()
            .join("\n");
        let expected = |after, path: &str| -> Result<String> {
            let (_, before, next) = AUDIT261
                .iter()
                .chain(CHANGES)
                .find(|e| e.0 == path)
                .context("fixture path")?;
            Ok(if after { *next } else { *before }.into())
        };
        exact_changes(&changed, expected).unwrap();
        assert_eq!(
            record(&changed)["standalone_audit_source_commit"],
            AUDIT261_COMMIT
        );
        for &(path, _, _) in AUDIT261 {
            let incomplete = changed
                .lines()
                .filter(|p| *p != path)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(exact_changes(&incomplete, expected).is_err());
            for before in [false, true] {
                assert!(
                    exact_changes(&changed, |after, p| if p == path && before == after {
                        Ok("wrong mode or blob".into())
                    } else {
                        expected(after, p)
                    })
                    .is_err()
                );
            }
        }
        let old = CHANGES.iter().map(|e| e.0).collect::<Vec<_>>().join("\n");
        exact_changes(&old, original_entry).unwrap();
        assert!(exact_changes(&old, expected).is_err());
        assert!(exact_changes(&changed, original_entry).is_err());
        assert!(
            exact_changes(
                &format!("{changed}\njetstreamer-firehose/src/lib.rs"),
                expected
            )
            .is_err()
        );
        assert_eq!(
            record(&old)["schema"],
            "horizon-reader-exact-operator-equivalence205-v1"
        );
    }
    #[test]
    fn manifest_lock_guard_and_modes_are_exact_not_allowlisted_paths() {
        for (path, _, _) in CHANGES {
            exact_changes(path, original_entry).unwrap();
            for wrong_side in [false, true] {
                assert!(
                    exact_changes(path, |after, p| {
                        let value = original_entry(after, p)?;
                        Ok(if after == wrong_side {
                            if value.is_empty() {
                                format!("100644 blob {}\t{p}", "a".repeat(40))
                            } else {
                                value.replacen("100644", "100755", 1)
                            }
                        } else {
                            value
                        })
                    })
                    .is_err()
                );
                assert!(
                    exact_changes(path, |after, p| {
                        let value = original_entry(after, p)?;
                        Ok(if after == wrong_side {
                            format!("{value} changed")
                        } else {
                            value
                        })
                    })
                    .is_err()
                );
            }
        }
    }
}
