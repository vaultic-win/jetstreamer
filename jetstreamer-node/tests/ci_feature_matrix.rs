//! Keep isolated node modes covered when adding a new compile-time route.
use std::collections::BTreeSet;

fn declared_features(manifest: &str) -> BTreeSet<&str> {
    let features = manifest
        .split_once("[features]\n")
        .expect("node feature table")
        .1
        .split("\n[")
        .next()
        .unwrap();
    features
        .lines()
        .filter_map(|line| line.split('#').next()?.split_once('='))
        .map(|(key, _)| key.trim())
        .filter(|key| *key != "default")
        .collect()
}

fn entries(matrix: &str) -> Vec<(&str, &str)> {
    matrix
        .split("          - name: ")
        .skip(1)
        .map(|entry| {
            let quoted = |prefix| {
                entry
                    .lines()
                    .find_map(|line| line.trim().strip_prefix(prefix)?.strip_suffix('"'))
                    .expect("matrix field")
            };
            (quoted("scope: \""), quoted("flags: \""))
        })
        .collect()
}

#[test]
fn ci_covers_every_declared_node_mode_independently() {
    let declared = declared_features(include_str!("../Cargo.toml"));
    assert!(!declared.is_empty());

    let workflow = include_str!("../../.github/workflows/rust.yaml");
    let matrix = workflow
        .split_once("matrix: &rust-feature-matrix\n")
        .expect("shared Rust matrix")
        .1
        .split_once("    steps:")
        .expect("end of shared matrix")
        .0;
    let entries = entries(matrix);
    let node_flags: Vec<_> = entries
        .iter()
        .filter(|(scope, _)| *scope == "-p jetstreamer-node")
        .map(|(_, flags)| *flags)
        .collect();
    let covered: BTreeSet<_> = node_flags
        .iter()
        .map(|flags| {
            flags
                .strip_prefix("--features ")
                .expect("isolated node feature")
        })
        .collect();
    assert_eq!(
        declared, covered,
        "every node feature needs an isolated CI job"
    );
    for feature in declared {
        assert_eq!(
            node_flags
                .iter()
                .filter(|flags| **flags == format!("--features {feature}"))
                .count(),
            1,
            "feature must have exactly one isolated entry: {feature}"
        );
    }
    assert!(matrix.contains("scope: \"--workspace\"\n            flags: \"\""));
    assert!(matrix.contains(
        "scope: \"--workspace --exclude jetstreamer-node --exclude jetstreamer-horizon-observe\"\n            flags: \"--all-features\""
    ));
    assert_eq!(workflow.matches("matrix: *rust-feature-matrix").count(), 2);
    assert_eq!(
        workflow
            .matches("${{ matrix.scope }} ${{ matrix.flags }}")
            .count(),
        3,
        "check, test and clippy must consume the same feature matrix"
    );
    assert!(workflow.contains("if: matrix.examples"));
    assert!(workflow.contains("--example reencode_archive"));
    assert!(workflow.contains("--example verify_archive"));
    assert!(workflow.contains("shell: bash\n        run: cargo test"));
    assert!(workflow.contains("2>&1 | tee \"$RUNNER_TEMP/rust-test.log\""));
    assert!(
        workflow.contains("name: Report test failure in check annotations\n        if: failure()")
    );
    assert!(workflow.contains("::error title=Rust test failure details::%s"));
}

#[test]
fn observer_feature_families_are_complete_and_epoch223_remains_isolated() {
    let declared = declared_features(include_str!("../../jetstreamer-horizon-observe/Cargo.toml"));
    let workflow = include_str!("../../.github/workflows/rust.yaml");
    let matrix = workflow
        .split_once("matrix: &rust-feature-matrix\n")
        .unwrap()
        .1
        .split_once("    steps:")
        .unwrap()
        .0;
    let entries = entries(matrix);
    let observer: Vec<Vec<_>> = entries
        .iter()
        .filter(|(scope, _)| *scope == "-p jetstreamer-horizon-observe")
        .map(|(_, flags)| {
            flags
                .strip_prefix("--features ")
                .expect("explicit observer family")
                .split(',')
                .collect()
        })
        .collect();
    let covered: BTreeSet<_> = observer.iter().flatten().copied().collect();
    assert_eq!(declared, covered, "all observer features need CI coverage");
    let isolated: Vec<_> = observer
        .iter()
        .filter(|family| family.contains(&"epoch223-tail-snapshot-tests"))
        .collect();
    assert_eq!(
        isolated.len(),
        1,
        "epoch223 needs exactly one explicit family"
    );
    assert_eq!(
        isolated[0].as_slice(),
        ["epoch223-tail-snapshot-tests"],
        "exclusive snapshot profiles must not be combined"
    );
}
