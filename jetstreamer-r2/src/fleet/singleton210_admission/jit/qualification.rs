//! Actual source-bound package QA for the narrow JIT role. The ordinary tool
//! validator authenticates sealed report/result/log copies; no asserted passed
//! flag substitutes for the real full-test and strict-Clippy result records.
use super::*;
pub(super) const REQUIRED: [&str; 10] = [
    "fleet::singleton210_admission::custody::tests::full210_prehashed_tuple_covers_content_identity_custody_and_exact_mode",
    "fleet::singleton210_admission::custody::tests::full210_prehashed_descriptor_cannot_hide_path_replacement_or_mode_change",
    "fleet::singleton210_admission::custody::tests::full210_prehashed_input_changed_through_preexisting_writer_is_rejected",
    "fleet::singleton210_admission::jit::tests::full210_jit_roster_cannot_omit_duplicate_replace_or_add_a_live_owner",
    "fleet::singleton210_admission::jit::tests::full210_jit_selection_rejects_foreign_stale_tripped_and_replaced_guard",
    "fleet::singleton210_admission::jit::tests::full210_jit_wire_cannot_import_guard_choices_skip_checks_or_gain_authority",
    "fleet::singleton210_admission::jit::issuer::tests::full210_jit_same_process_proof_rejects_replaced_caller_and_effective_contract",
    "fleet::singleton210_admission::jit::issuer::tests::full210_jit_caller_scope_and_native_capabilities_are_closed",
    "fleet::singleton210_admission::jit::qualification::tests::full210_jit_role_rejects_failed_foreign_source_and_filtered_actual_qa",
    "fleet::singleton210_admission::jit::qualification::tests::full210_jit_role_needs_exact_passed_regressions_and_unfiltered_summary",
];
fn binding(v: &Value, key: &str) -> Result<BoundFile> {
    Ok(serde_json::from_value(v[key].clone())?)
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("210 JIT QA missing string: {key}"))
}
fn metadata(b: &BoundFile) -> Result<Value> {
    native210::immutable_json(b)
}
fn log(b: &BoundFile) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "210 JIT QA log lost root immutable custody"
    );
    let raw = read_stable_bounded(&b.path, 32 << 20, "210 JIT actual QA log")?;
    ensure!(
        hex_lower(&Sha256::digest(&raw)) == b.sha256,
        "210 JIT QA log digest differs"
    );
    Ok(raw)
}
fn source_identity(role: &Value, component: &Value, source: &Value, qa: &Value) -> Result<()> {
    let commit = string(role, "source_commit")?;
    let tree = string(role, "source_tree")?;
    ensure!(
        is_lower_hex(commit, 40)
            && is_lower_hex(tree, 40)
            && component["source_revision"] == commit,
        "210 JIT role/component source revision differs"
    );
    for (v, key) in [
        (source, "source_revision_pointer"),
        (qa, "qa_revision_pointer"),
    ] {
        let pointer = string(component, key)?;
        ensure!(
            v.pointer(pointer) == Some(&json!(commit)),
            "210 JIT actual capture/QA source commit differs"
        );
    }
    for (v, key) in [(source, "source_tree_pointer"), (qa, "qa_tree_pointer")] {
        let pointer = string(role, key)?;
        ensure!(
            matches!(
                pointer,
                "/source/tree" | "/source_tree" | "/tree" | "/final_tree"
            ) && v.pointer(pointer) == Some(&json!(tree)),
            "210 JIT actual capture/QA source tree differs"
        );
    }
    Ok(())
}
fn linked_result(
    qa: &Value,
    component: &Value,
    result: &BoundFile,
    expected_log: &BoundFile,
) -> Result<()> {
    let copies = component["qa_files"]
        .as_array()
        .context("210 JIT QA result copy ledger missing")?;
    let entries = copies
        .iter()
        .filter(|f| f["copy"] == private157::binding(result))
        .collect::<Vec<_>>();
    ensure!(
        entries.len() == 1,
        "210 JIT actual result is not a unique approved sealed QA copy"
    );
    let original = &entries[0]["original"];
    let logs: Vec<BoundFile> = serde_json::from_value(component["qa_logs"].clone())?;
    ensure!(
        logs.contains(expected_log),
        "210 JIT actual log is not an approved sealed QA log"
    );
    let matching = if let Some(rows) = qa["actual_results"].as_array() {
        rows.iter()
            .filter(|r| r["raw_result"] == *original && r["exit_code"] == 0)
            .count()
    } else if let Some(rows) = qa["stages"].as_array() {
        rows.iter()
            .filter(|r| {
                r["result_path"] == original["path"]
                    && r["result_sha256"] == original["sha256"]
                    && r["exit_code"] == 0
            })
            .count()
    } else {
        bail!("210 JIT requires actual linked result records, not a flag-only QA command list")
    };
    ensure!(
        matching == 1,
        "210 JIT selected result is not linked exactly once by the actual passed QA report"
    );
    Ok(())
}
fn command_scope(result: &Value, commit: &str, log: &BoundFile, clippy: bool) -> Result<()> {
    ensure!(
        result["exit_code"] == 0
            && result.get("stop_reason") == Some(&Value::Null)
            && result["source_revision"] == commit
            && result["log_sha256"] == log.sha256,
        "210 JIT actual QA failed, stopped or changed source/log"
    );
    let args = result["argv"]
        .as_array()
        .context("210 JIT QA actual argv missing")?
        .iter()
        .map(|v| v.as_str().context("210 JIT actual argv is not text"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        matches!(
            args.first().copied(),
            Some("cargo" | "/home/ubuntu/.cargo/bin/cargo")
        ) && args.get(1).copied() == Some(if clippy { "clippy" } else { "test" }),
        "210 JIT QA command does not run the actual package checker"
    );
    let split = args.iter().position(|s| *s == "--").unwrap_or(args.len());
    let cargo = &args[..split];
    let package = cargo
        .windows(2)
        .filter(|p| matches!(p[0], "-p" | "--package"))
        .collect::<Vec<_>>();
    ensure!(
        package.len() == 1
            && package[0][1] == "jetstreamer-r2"
            && !cargo
                .iter()
                .any(|s| s.starts_with("--package=") || *s == "--workspace" || *s == "--exclude"),
        "210 JIT QA selected a foreign/ambiguous package"
    );
    for needed in ["--release", "--frozen", "--locked", "--offline"] {
        ensure!(
            cargo.contains(&needed),
            "210 JIT QA lacks the reviewed frozen release invocation: {needed}"
        );
    }
    if clippy {
        ensure!(
            cargo.contains(&"--all-targets")
                && cargo.contains(&"--all-features")
                && split < args.len()
                && args[split + 1..]
                    .windows(2)
                    .any(|p| p == ["-D", "warnings"]),
            "210 JIT actual Clippy is not strict all-target/all-feature QA"
        );
    } else {
        ensure!(
            !cargo.iter().any(|a| [
                "--features",
                "--all-features",
                "--no-default-features",
                "--bin",
                "--test",
                "--example",
                "--bench",
                "--lib",
                "--doc",
                "--no-run",
                "--list"
            ]
            .iter()
            .any(|k| *a == *k || a.starts_with(&format!("{k}=")))),
            "210 JIT requires the actual full default package tests, not a filtered build or listing"
        );
        if split < args.len() {
            ensure!(
                args[split + 1..]
                    .iter()
                    .all(|a| matches!(*a, "--test-threads=1" | "--nocapture")),
                "210 JIT actual default tests have a name/filter/ignored override"
            );
        }
    }
    Ok(())
}
fn required_tests(raw: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(raw)?;
    let passed = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("test ")?.strip_suffix(" ... ok"))
        .collect::<BTreeSet<_>>();
    ensure!(
        REQUIRED.iter().all(|name| passed.contains(name)),
        "210 JIT exact required regressions did not actually pass in the full default run"
    );
    let mut total_passed = 0u64;
    for line in text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("test result: ok. "))
    {
        let f = line.split("; ").collect::<Vec<_>>();
        ensure!(f.len() >= 5, "210 JIT full test summary truncated");
        let count = |index: usize, label: &str| -> Result<u64> {
            Ok(f[index]
                .strip_suffix(label)
                .context("210 JIT full test summary label differs")?
                .parse()?)
        };
        ensure!(
            count(1, " failed")? == 0 && count(4, " filtered out")? == 0,
            "210 JIT default test log has failures or filters"
        );
        total_passed = total_passed
            .checked_add(count(0, " passed")?)
            .context("210 JIT QA passed count overflow")?;
    }
    ensure!(
        total_passed >= REQUIRED.len() as u64,
        "210 JIT default test log has no actual passed group"
    );
    Ok(())
}
pub(super) fn validate(role: &issuer::Role) -> Result<Value> {
    let q = metadata(&role.qualification)?;
    ensure!(
        q["schema"] == "jetstreamer-full210-jit-issuer-role-qualification-v1"
            && q["role"] == "singleton210-jit-admission"
            && q["helper"] == private157::binding(&role.runner),
        "210 JIT role qualification changed its exact helper or purpose"
    );
    for key in [
        "publication_authorized",
        "replay_launch_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(q[key] == false, "210 JIT role borrows lifecycle authority");
    }
    let component_binding = binding(&q, "component_qualification")?;
    // The existing stage label selects jetstreamer-r2 package source QA only.
    // This call executes no uploader and confers no network/publication authority.
    assembly204_recovery::qualified_delivery_tool("upload", &role.runner, &component_binding)?;
    let component = metadata(&component_binding)?;
    let source = metadata(&binding(&component, "source_capture")?)?;
    let report_binding = binding(&component, "qa_report")?;
    ensure!(
        binding(&q, "source_qa")? == report_binding,
        "210 JIT role bound a different QA report"
    );
    let qa = metadata(&report_binding)?;
    source_identity(&q, &component, &source, &qa)?;
    let test_result = binding(&q, "full_default_result")?;
    let test_log = binding(&q, "full_default_log")?;
    let clippy_result = binding(&q, "strict_clippy_result")?;
    let clippy_log = binding(&q, "strict_clippy_log")?;
    for (result, log, clippy) in [
        (&test_result, &test_log, false),
        (&clippy_result, &clippy_log, true),
    ] {
        linked_result(&qa, &component, result, log)?;
        command_scope(
            &metadata(result)?,
            string(&q, "source_commit")?,
            log,
            clippy,
        )?;
    }
    required_tests(&log(&test_log)?)?;
    Ok(
        json!({"role_qualification":role.qualification,"component_qualification":component_binding,"source_commit":q["source_commit"],
        "source_tree":q["source_tree"],"source_capture":component["source_capture"],"source_qa":report_binding,
        "full_default_result":test_result,"full_default_log":test_log,"strict_clippy_result":clippy_result,"strict_clippy_log":clippy_log,
        "required_jit_test_names":REQUIRED,"qa_semantics_authenticated":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full210_jit_role_rejects_failed_foreign_source_and_filtered_actual_qa() {
        let log = BoundFile {
            path: "/sealed/log".into(),
            sha256: "a".repeat(64),
        };
        let commit = "b".repeat(40);
        let r = json!({"argv":["cargo","test","-p","jetstreamer-r2","--release","--frozen","--locked","--offline","--","--test-threads=1"],"exit_code":0,"stop_reason":null,"source_revision":commit,"log_sha256":log.sha256});
        command_scope(&r, &commit, &log, false).unwrap();
        for (key, value) in [
            ("exit_code", json!(1)),
            ("source_revision", json!("c".repeat(40))),
            ("stop_reason", json!("timeout")),
            ("log_sha256", json!("d".repeat(64))),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(command_scope(&bad, &commit, &log, false).is_err());
        }
        let mut filtered = r.clone();
        filtered["argv"]
            .as_array_mut()
            .unwrap()
            .push(json!("some_test"));
        assert!(command_scope(&filtered, &commit, &log, false).is_err());
        let q = json!({"source_commit":commit,"source_tree":"e".repeat(40),"source_tree_pointer":"/tree","qa_tree_pointer":"/tree"});
        let c = json!({"source_revision":commit,"source_revision_pointer":"/commit","qa_revision_pointer":"/commit"});
        let source = json!({"commit":commit,"tree":"e".repeat(40)});
        source_identity(&q, &c, &source, &source).unwrap();
        for key in ["commit", "tree"] {
            let mut bad = source.clone();
            bad[key] = json!("f".repeat(40));
            assert!(source_identity(&q, &c, &source, &bad).is_err());
        }
    }
    #[test]
    fn full210_jit_role_needs_exact_passed_regressions_and_unfiltered_summary() {
        let mut text = REQUIRED
            .iter()
            .map(|n| format!("test {n} ... ok\n"))
            .collect::<String>();
        text.push_str(&format!("test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0s\n",REQUIRED.len()));
        required_tests(text.as_bytes()).unwrap();
        for bad in [
            text.replace(REQUIRED[0], "foreign_test"),
            text.replace("0 failed", "1 failed"),
            text.replace("0 filtered out", "1 filtered out"),
            text.replace(" ... ok", " ... ignored"),
        ] {
            assert!(required_tests(bad.as_bytes()).is_err());
        }
    }
}
