use super::*;
fn actual() -> Value {
    serde_json::from_str(include_str!("actual_integrity.json")).unwrap()
}
fn check(v: &Value) -> Result<()> {
    shape(
        &v["inputs"],
        &v["checkpoint"],
        &v["tracked"],
        &v["rechecks"],
        &v["command"],
        &v["capture"],
        &v["preflight"],
    )
}
#[test]
fn actual_scoped_pre_build_pins_agree_with_capture_and_final_rechecks() {
    let v = actual();
    check(&v).unwrap();
    let records = v["rechecks"]["records"].as_array().unwrap();
    assert!(records
        .iter()
        .any(|r| r["path"].as_str().unwrap().ends_with("/bin/rustc")));
    for tool in ["cargo", "rustfmt"] {
        assert!(!records.iter().any(|r| r["path"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/bin/{tool}"))));
    }
}
#[test]
fn changed_source_config_tool_workflow_and_after_capture_facts_fail_closed() {
    let v = actual();
    for (path, value) in [
        ("/inputs/source_commit", json!("a".repeat(40))),
        (
            "/inputs/script_sha256/run-bounded-build-capture.py",
            json!("a".repeat(64)),
        ),
        ("/checkpoint/files/Cargo.lock", json!("a".repeat(64))),
        ("/tracked/tracked_files/0/sha256", json!("a".repeat(64))),
        ("/rechecks/all_reopened_and_rehashed", json!(false)),
        ("/rechecks/records/0/identity_unchanged", json!(false)),
        ("/command/static_inputs_sha256", json!("a".repeat(64))),
        ("/capture/capture_workflow_unchanged", json!(false)),
        ("/preflight/configuration/0/sha256", json!("a".repeat(64))),
    ] {
        let mut bad = v.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(check(&bad).is_err(), "accepted {path}");
    }
    for tool in ["cargo", "rustc", "rustfmt"] {
        let mut bad = v.clone();
        bad["inputs"]["input_sha256"][format!(
            "/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/{tool}"
        )] = json!("a".repeat(64));
        assert!(
            check(&bad).is_err(),
            "accepted changed wrapper-checked {tool}"
        );
    }
    for suffix in ["/.cargo/config.toml", "/bin/rustc", "/Cargo.lock"] {
        let mut bad = v.clone();
        bad["rechecks"]["records"]
            .as_array_mut()
            .unwrap()
            .retain(|r| !r["path"].as_str().unwrap().ends_with(suffix));
        assert!(check(&bad).is_err(), "accepted missing final {suffix}");
    }
}
