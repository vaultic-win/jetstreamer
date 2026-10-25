//! Read genuine completed component QA without rewriting its saved evidence.
use super::*;

const CARGO: &str = "/home/ubuntu/.cargo/bin/cargo";

/// Explicit copy custody: raw reports retain their original paths. Both bindings
/// carry the identical digest; the caller authenticates each copy in the tool seal.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceFile {
    pub original: BoundFile,
    pub copy: BoundFile,
}

fn argv(value: &Value) -> Result<Vec<&str>> {
    value
        .as_array()
        .context("204 tool QA argv missing")?
        .iter()
        .map(|v| v.as_str().context("204 tool QA argv is not a string"))
        .collect()
}
fn relevant(args: &[&str], component: &str) -> Option<bool> {
    let kind = match args.get(1).copied() {
        Some("test") => false,
        Some("clippy") => true,
        _ => return None,
    };
    let package = args
        .windows(2)
        .any(|p| matches!(p[0], "-p" | "--package") && p[1] == component)
        || args
            .iter()
            .any(|a| a.strip_prefix("--package=") == Some(component));
    package.then_some(kind)
}
fn completed(
    args: &[&str],
    component: &str,
    exit: &Value,
    log: &str,
    logs: &[BoundFile],
) -> Result<Option<bool>> {
    let Some(clippy) = relevant(args, component) else {
        return Ok(None);
    };
    ensure!(
        matches!(args.first().copied(), Some("cargo" | CARGO)),
        "204 tool QA uses an unapproved Cargo executable"
    );
    ensure!(exit == 0, "204 component QA command failed");
    ensure!(
        !clippy || args.windows(2).any(|p| p == ["-D", "warnings"]) || args.contains(&"-Dwarnings"),
        "204 component Clippy did not deny warnings"
    );
    ensure!(
        is_lower_hex(log, 64) && logs.iter().any(|b| b.sha256 == log),
        "204 successful component QA lacks its actual sealed log"
    );
    Ok(Some(clippy))
}
fn origin(row: &Value, key: &str) -> Result<BoundFile> {
    Ok(serde_json::from_value(row[key].clone())?)
}
fn resolve<'a>(wanted: &BoundFile, files: &'a [EvidenceFile]) -> Result<&'a BoundFile> {
    let found = files
        .iter()
        .filter(|f| f.original == *wanted)
        .collect::<Vec<_>>();
    ensure!(
        found.len() == 1,
        "204 QA original file has no unique sealed copy"
    );
    Ok(&found[0].copy)
}

/// Parent has already bound the report's exact source pointer, the artifact and
/// source capture, and authenticated every declared result/log copy in its seal.
pub(super) fn validate(
    qa: &Value,
    source: &str,
    component: &str,
    logs: &[BoundFile],
    files: &[EvidenceFile],
    mut read_result: impl FnMut(&BoundFile) -> Result<Value>,
) -> Result<()> {
    ensure!(is_lower_hex(source, 40), "204 tool QA source digest");
    let mut originals = BTreeSet::new();
    let mut copies = BTreeSet::new();
    for f in files {
        ensure!(
            f.original.path.is_absolute()
                && f.copy.path.is_absolute()
                && is_lower_hex(&f.original.sha256, 64)
                && f.original.sha256 == f.copy.sha256
                && originals.insert(f.original.path.clone())
                && copies.insert(f.copy.path.clone()),
            "204 QA original/copy binding is invalid or duplicated"
        );
    }
    let shapes = ["commands", "stages", "actual_results"];
    let selected = shapes
        .iter()
        .filter(|key| qa.get(**key).is_some())
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "204 tool QA report shape is missing or ambiguous"
    );
    let shape = *selected[0];
    let rows = qa[shape].as_array().context("204 tool QA rows missing")?;
    let mut test = false;
    let mut clippy = false;
    let mut ids = BTreeSet::new();
    if shape == "stages" {
        ensure!(
            qa["natural_exit_code"] == 0,
            "204 staged QA did not finish successfully"
        );
    } else if shape == "actual_results" {
        ensure!(
            qa["source_qa_passed"] == true,
            "204 actual-result QA is not passed"
        );
    }
    for row in rows {
        let (args, exit, log) = if shape == "commands" {
            let args = argv(&row["command"])?;
            if relevant(&args, component).is_none() {
                continue;
            }
            let log = row["log_sha256"]
                .as_str()
                .context("204 QA log digest absent")?;
            (args, &row["exit_code"], log)
        } else {
            let id = row["id"].as_str().context("204 QA stage ID absent")?;
            ensure!(
                !id.is_empty() && ids.insert(id),
                "204 QA stage ID duplicated/empty"
            );
            let (result_origin, log_origin) = if shape == "stages" {
                (
                    BoundFile {
                        path: s(row, "result_path")?.into(),
                        sha256: s(row, "result_sha256")?.into(),
                    },
                    BoundFile {
                        path: s(row, "log_path")?.into(),
                        sha256: s(row, "log_sha256")?.into(),
                    },
                )
            } else {
                ensure!(
                    row["actual_source_commit"] == source,
                    "204 actual-result QA has foreign source"
                );
                (origin(row, "raw_result")?, origin(row, "log")?)
            };
            let result_copy = resolve(&result_origin, files)?;
            let log_copy = resolve(&log_origin, files)?;
            ensure!(
                logs.contains(log_copy),
                "204 QA stage log is not an approved sealed log"
            );
            let result = read_result(result_copy)?;
            ensure!(
                row["exit_code"] == 0
                    && result["exit_code"] == 0
                    && result.get("stop_reason") == Some(&Value::Null)
                    && result["source_revision"] == source
                    && result["log_sha256"] == log_origin.sha256,
                "204 QA stage result failed, stopped, changed source or log"
            );
            if shape == "actual_results" {
                ensure!(
                    row["argv"] == result["argv"],
                    "204 QA report/result argv differ"
                );
            }
            // Own the loaded result until its borrowed argv/log have been checked.
            let args = argv(&result["argv"])?;
            if let Some(is_clippy) = completed(
                &args,
                component,
                &result["exit_code"],
                &log_origin.sha256,
                logs,
            )? {
                clippy |= is_clippy;
                test |= !is_clippy;
            }
            continue;
        };
        if let Some(is_clippy) = completed(&args, component, exit, log, logs)? {
            clippy |= is_clippy;
            test |= !is_clippy;
        }
    }
    ensure!(
        test && clippy,
        "204 tool lacks successful source-bound component tests and strict Clippy"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(path: &str, byte: char) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: byte.to_string().repeat(64),
        }
    }
    type Fixture = (
        Value,
        Vec<BoundFile>,
        Vec<EvidenceFile>,
        BTreeMap<PathBuf, Value>,
    );
    fn fixture(actual: bool) -> Fixture {
        let mut rows = Vec::new();
        let mut files = Vec::new();
        let mut logs = Vec::new();
        let mut results = BTreeMap::new();
        for (index, command) in ["test", "clippy"].iter().enumerate() {
            let result = bound(
                &format!("/original/{index}.json"),
                if index == 0 { 'a' } else { 'b' },
            );
            let log = bound(
                &format!("/original/{index}.log"),
                if index == 0 { 'c' } else { 'd' },
            );
            let result_copy = BoundFile {
                path: format!("/sealed/{index}.json").into(),
                sha256: result.sha256.clone(),
            };
            let log_copy = BoundFile {
                path: format!("/sealed/{index}.log").into(),
                sha256: log.sha256.clone(),
            };
            let mut args = vec![CARGO, command, "--release", "-p", "jetstreamer-horizon"];
            if index == 1 {
                args.extend(["--", "-D", "warnings"]);
            }
            let record = json!({"argv":args,"exit_code":0,"stop_reason":null,"source_revision":"e".repeat(40),"log_sha256":log.sha256});
            results.insert(result_copy.path.clone(), record);
            rows.push(if actual {
                json!({"id":format!("{index}"),"actual_source_commit":"e".repeat(40),"argv":args,"exit_code":0,"raw_result":result,"log":log,"summary":["test result: ok. 7 passed; 0 failed; 1 ignored"]})
            } else {
                json!({"id":format!("{index}"),"result_path":result.path,"result_sha256":result.sha256,"log_path":log.path,"log_sha256":log.sha256,"exit_code":0,"final_test_group":{"passed":7,"failed":0,"ignored":1}})
            });
            files.push(EvidenceFile {
                original: result,
                copy: result_copy,
            });
            files.push(EvidenceFile {
                original: log,
                copy: log_copy.clone(),
            });
            logs.push(log_copy);
        }
        let qa = if actual {
            json!({"source_qa_passed":true,"actual_results":rows})
        } else {
            json!({"natural_exit_code":0,"stages":rows})
        };
        (qa, logs, files, results)
    }
    fn check(
        qa: &Value,
        logs: &[BoundFile],
        files: &[EvidenceFile],
        results: &BTreeMap<PathBuf, Value>,
    ) -> Result<()> {
        validate(
            qa,
            &"e".repeat(40),
            "jetstreamer-horizon",
            logs,
            files,
            |b| {
                results
                    .get(&b.path)
                    .cloned()
                    .context("missing actual result")
            },
        )
    }
    #[test]
    fn genuine_stages_and_actual_results_keep_ignored_counts_and_original_bytes() {
        for actual in [false, true] {
            let (qa, logs, files, results) = fixture(actual);
            let before = qa.clone();
            check(&qa, &logs, &files, &results).unwrap();
            assert_eq!(qa, before);
        }
    }
    #[test]
    fn legacy_completed_commands_still_require_component_tests_and_strict_clippy() {
        let log = bound("/sealed/legacy.log", 'a');
        let mut qa = json!({"commands":[
            {"command":["cargo","test","-p","jetstreamer-horizon"],"exit_code":0,"log_sha256":log.sha256},
            {"command":[CARGO,"clippy","-p","jetstreamer-horizon","--","-Dwarnings"],"exit_code":0,"log_sha256":log.sha256}]});
        check(&qa, std::slice::from_ref(&log), &[], &BTreeMap::new()).unwrap();
        qa["commands"][0]["exit_code"] = json!(101);
        assert!(check(&qa, &[log], &[], &BTreeMap::new()).is_err());
    }
    #[test]
    fn raw_stage_source_status_stop_log_and_cargo_are_not_assertions() {
        let (qa, logs, files, results) = fixture(false);
        for (key, bad) in [
            ("source_revision", json!("f".repeat(40))),
            ("exit_code", json!(101)),
            ("stop_reason", json!("timeout")),
            ("log_sha256", json!("f".repeat(64))),
            (
                "argv",
                json!(["/tmp/cargo", "test", "-p", "jetstreamer-horizon"]),
            ),
            (
                "argv",
                json!([
                    "/other/.cargo/bin/cargo",
                    "test",
                    "-p",
                    "jetstreamer-horizon"
                ]),
            ),
            ("argv", json!([CARGO, "test", "-p", "jetstreamer-r2"])),
            ("argv", json!([CARGO, "test", 4, "jetstreamer-horizon"])),
        ] {
            let mut bad_results = results.clone();
            bad_results.get_mut(&files[0].copy.path).unwrap()[key] = bad;
            assert!(check(&qa, &logs, &files, &bad_results).is_err(), "{key}");
        }
        let mut loose_clippy = results.clone();
        loose_clippy.get_mut(&files[2].copy.path).unwrap()["argv"] =
            json!([CARGO, "clippy", "-p", "jetstreamer-horizon"]);
        assert!(check(&qa, &logs, &files, &loose_clippy).is_err());
        let mut stopped = results.clone();
        stopped
            .get_mut(&files[0].copy.path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("stop_reason");
        assert!(check(&qa, &logs, &files, &stopped).is_err());
    }
    #[test]
    fn missing_logs_mappings_duplicate_ids_and_mixed_shapes_fail_closed() {
        let (qa, logs, files, results) = fixture(false);
        assert!(check(&qa, &[], &files, &results).is_err());
        assert!(check(&qa, &logs, &files[1..], &results).is_err());
        let mut duplicate = files.clone();
        duplicate.push(files[0].clone());
        assert!(check(&qa, &logs, &duplicate, &results).is_err());
        let mut bad = qa.clone();
        bad["stages"][1]["id"] = json!("0");
        assert!(check(&bad, &logs, &files, &results).is_err());
        bad = qa.clone();
        bad["commands"] = json!([]);
        assert!(check(&bad, &logs, &files, &results).is_err());
        bad = qa;
        bad["stages"][0]["result_sha256"] = json!("f".repeat(64));
        assert!(check(&bad, &logs, &files, &results).is_err());
    }
    #[test]
    fn actual_result_argv_and_source_must_match_raw_sealed_result() {
        let (qa, logs, files, results) = fixture(true);
        for key in ["actual_source_commit", "argv", "exit_code"] {
            let mut bad = qa.clone();
            bad["actual_results"][0][key] = match key {
                "argv" => json!(["cargo", "test", "-p", "jetstreamer-horizon"]),
                "exit_code" => json!(1),
                _ => json!("f".repeat(40)),
            };
            assert!(check(&bad, &logs, &files, &results).is_err());
        }
    }
}
