//! Saved original guard property and the history reader's complete ExecStart.
//! No current service, resource observation, or privileged filesystem reads.
use super::*;

fn fixture() -> (BTreeMap<String, String>, Value, Value) {
    let value: Value =
        serde_json::from_str(include_str!("fixtures/original-guard-command.json")).unwrap();
    (
        serde_json::from_value(value["properties"].clone()).unwrap(),
        value["history"].clone(),
        value["plan"].clone(),
    )
}

#[test]
fn rebase207_effective_command_accepts_actual_original_terminal_history_shape() {
    let (properties, history, plan) = fixture();
    let expected = text(&history, "expected_exec_start").unwrap();
    assert_ne!(properties["ExecStart"], expected);
    assert!(expected.contains(" ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "));
    assert!(properties["ExecStart"].contains(" ; pid=2255477 ; "));
    // Demonstrate the real failure: a full expected property cannot be used
    // where the old comparator requires only the command argument prefix.
    assert!(!private_prefix::same_command(
        &json!(properties["ExecStart"]),
        expected,
    ));
    effective_guard_command(&properties, &history, &plan).unwrap();
    let mut reset = properties;
    reset.insert("ExecStart".into(), expected.to_owned());
    effective_guard_command(&reset, &history, &plan).unwrap();
}

#[test]
fn rebase207_effective_command_rejects_changed_executable_arguments_and_plan() {
    let (properties, history, plan) = fixture();
    for (old, replacement) in [
        (singleton207::GUARD, "/sealed/foreign-guard"),
        (
            "/var/lib/jetstreamer/horizon-singleton207-guard-plan-retry-v1/guard-plan.json",
            "/var/lib/jetstreamer/another-plan/guard-plan.json",
        ),
        (
            OLD_PLAN_SHA,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            singleton207::GUARD_SHA,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ),
        (
            " --plan-sha256 ",
            " --extra-unreviewed-argument --plan-sha256 ",
        ),
        (" ; ignore_errors=no", " ; ignore_errors=yes"),
    ] {
        let mut changed = properties.clone();
        assert!(changed["ExecStart"].contains(old), "fixture lacks {old}");
        changed.insert(
            "ExecStart".into(),
            changed["ExecStart"].replace(old, replacement),
        );
        assert!(
            effective_guard_command(&changed, &history, &plan).is_err(),
            "changed command {old}"
        );
    }
    let mut changed = properties;
    changed
        .get_mut("ExecStart")
        .unwrap()
        .push_str(" ; second-command=/bin/true");
    assert!(effective_guard_command(&changed, &history, &plan).is_err());
}

#[test]
fn rebase207_effective_command_keeps_receipt_directory_and_issuer_exact() {
    let (properties, history, plan) = fixture();
    let mut changed = properties.clone();
    changed.insert(
        "ReadWritePaths".into(),
        "/var/lib/jetstreamer/foreign-receipts".into(),
    );
    assert!(effective_guard_command(&changed, &history, &plan).is_err());
    let mut changed = history.clone();
    changed["executable"] = json!("/sealed/foreign-guard");
    assert!(effective_guard_command(&properties, &changed, &plan).is_err());
    let mut changed = history;
    changed["expected_exec_start"] = json!(
        properties["ExecStart"]
            .split_once(" ; ignore_errors=")
            .unwrap()
            .0
    );
    assert!(effective_guard_command(&properties, &changed, &plan).is_err());
}
