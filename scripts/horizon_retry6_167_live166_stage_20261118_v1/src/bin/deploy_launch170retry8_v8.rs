//! Preserve actual launcher qualification and seal epoch170 against the ranged audit.
//! Usage: deploy_launch170retry8_v8 /absolute/path/to/qualification-inputs.json
//! Does not book resources, capture a witness, change a service or start replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_170_guarded_launch_20261119_v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/launch-v8-evidence";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/launch-v8";
const OWN: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_launch170retry8_v8.rs";
const PHASES: [&str; 4] = ["test-build", "production", "tests", "clippy"];
const BUILD_BINDINGS: [&str; 4] = [
    "HORIZON_170_PREPARER_V5_SHA256",
    "HORIZON_170_PREPARER_V5_PROOF_SHA256",
    "HORIZON_170_PREPARER_V5_SOURCE_COMMIT",
    "HORIZON_170_PREPARER_V5_TESTS_PASSED",
];
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(c: &mut Command) -> Result<String> {
    let r = c.output()?;
    ensure!(
        r.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    Ok(String::from_utf8(r.stdout)?)
}
fn git(args: &[&str]) -> Result<String> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(args))
}
fn bind(path: &str) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn save(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(!name.is_empty() && !name.contains('/'), "leaf required");
    let path = format!("{STATE}/{name}");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(STATE)?.sync_all()?;
    bind(&path)
}
fn json_file(name: &str, value: &Value) -> Result<Value> {
    save(name, &serde_json::to_vec_pretty(value)?)
}
fn member(binding: &Value, name: &str, mode: u32) -> Result<Value> {
    let path = required_str(binding, "path")?;
    let expected = required_str(binding, "sha256")?;
    ensure!(
        sha(&fs::read(path)?) == expected,
        "bound member changed: {path}"
    );
    Ok(json!({"source":path,"name":name,"sha256":expected,"mode":mode}))
}
fn home_backed(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && fs::metadata(path)?.dev() == fs::metadata("/home/sol")?.dev(),
        "deployment path is not on the home filesystem: {}",
        path.display()
    );
    Ok(())
}
fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|text| !text.is_empty())
        .with_context(|| format!("mandatory string {key}"))
}
fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("expected configuration object")?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "required fields are exactly {keys:?}"
    );
    Ok(())
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}
fn absolute_path(value: &str) -> Result<()> {
    ensure!(
        Path::new(value).is_absolute()
            && Path::new(value)
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'.' | b'_' | b'-'))
            && !value.contains("//")
            && !value.ends_with('/'),
        "absolute unambiguous path required"
    );
    Ok(())
}
fn validate_inputs(inputs: &Value) -> Result<()> {
    exact_keys(
        inputs,
        &[
            "schema",
            "build_commit",
            "target_directory",
            "production_image",
            "test_image",
            "expected_tests_passed",
            "compile_environment",
            "qualifications",
        ],
    )?;
    ensure!(
        inputs["schema"] == "horizon-epoch170-launcher-deployment-input-v8",
        "wrong schema"
    );
    ensure!(
        lower_hex(required_str(inputs, "build_commit")?, 40),
        "actual full build commit required"
    );
    let target = required_str(inputs, "target_directory")?;
    absolute_path(target)?;
    for key in ["production_image", "test_image"] {
        exact_keys(&inputs[key], &["path", "sha256"])?;
        absolute_path(required_str(&inputs[key], "path")?)?;
        ensure!(
            lower_hex(required_str(&inputs[key], "sha256")?, 64),
            "actual {key} hash required"
        );
    }
    ensure!(
        inputs["production_image"]["path"]
            == format!("{target}/release/horizon-retry6-single170-launch"),
        "production target differs"
    );
    let test_suffix = required_str(&inputs["test_image"], "path")?
        .strip_prefix(&format!(
            "{target}/release/deps/horizon_retry6_single170_launch-"
        ))
        .context("test target differs")?;
    ensure!(lower_hex(test_suffix, 16), "Cargo test image name differs");
    ensure!(
        inputs["expected_tests_passed"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "observed positive launcher test count required"
    );
    let bindings = &inputs["compile_environment"];
    exact_keys(bindings, &BUILD_BINDINGS)?;
    for (key, length) in [
        (BUILD_BINDINGS[0], 64),
        (BUILD_BINDINGS[1], 64),
        (BUILD_BINDINGS[2], 40),
    ] {
        ensure!(
            lower_hex(required_str(bindings, key)?, length),
            "actual preparer binding required: {key}"
        );
    }
    let count = required_str(bindings, BUILD_BINDINGS[3])?;
    let parsed = count.parse::<u64>()?;
    ensure!(
        parsed >= 306 && parsed.to_string() == count,
        "actual complete preparer count required"
    );
    exact_keys(&inputs["qualifications"], &PHASES)?;
    let mut units = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for phase in PHASES {
        let qualification = &inputs["qualifications"][phase];
        exact_keys(qualification, &["unit", "invocation_id"])?;
        let unit = required_str(qualification, "unit")?;
        let iid = required_str(qualification, "invocation_id")?;
        ensure!(
            unit.ends_with(".service")
                && unit.len() > 8
                && unit
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                && units.insert(unit),
            "distinct explicit service required"
        );
        ensure!(
            lower_hex(iid, 32) && invocations.insert(iid),
            "four distinct genuine native invocations required"
        );
    }
    Ok(())
}
fn compile_environment(environment: &str, bindings: &Value) -> Result<()> {
    ensure!(
        !environment.contains("RUSTFLAGS=") && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
        "unqualified Rust flags"
    );
    for key in BUILD_BINDINGS {
        let value = required_str(bindings, key)?;
        let prefix = format!("{key}=");
        let found: Vec<_> = environment
            .split_whitespace()
            .filter(|word| word.starts_with(&prefix))
            .collect();
        ensure!(
            found.len() == 1 && found[0] == format!("{key}={value}"),
            "compile binding differs: {key}"
        );
    }
    Ok(())
}
fn full_test_count(log: &str, count: u64) -> Result<u64> {
    let summaries: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    ensure!(
        summaries.len() == 1,
        "one complete launcher test summary required"
    );
    let expected = format!(
        "test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
    );
    ensure!(
        count > 0
            && summaries[0]
                .strip_prefix(&expected)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(" finished in ")),
        "launcher tests incomplete"
    );
    Ok(count)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 2,
        "Root required; deploy_launch170retry8_v8 /absolute/path/to/qualification-inputs.json"
    );
    absolute_path(&args[1])?;
    let input_bytes = fs::read(&args[1])?;
    let inputs: Value = serde_json::from_slice(&input_bytes)?;
    validate_inputs(&inputs)?;
    let build_commit = required_str(&inputs, "build_commit")?;
    let image = required_str(&inputs["production_image"], "path")?;
    let image_sha = required_str(&inputs["production_image"], "sha256")?;
    let test_image = required_str(&inputs["test_image"], "path")?;
    let test_sha = required_str(&inputs["test_image"], "sha256")?;
    let target = required_str(&inputs, "target_directory")?;
    let expected_count = inputs["expected_tests_passed"]
        .as_u64()
        .context("test count")?;
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            PACKAGE,
            OWN
        ])?
        .is_empty(),
        "tracked tree changed"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        build_commit,
        "origin/account-updates",
    ])?;
    git(&[
        "diff",
        "--exit-code",
        build_commit,
        commit.trim(),
        "--",
        PACKAGE,
    ])?;
    ensure!(
        git(&["show", &format!("{}:{OWN}", commit.trim())])?.as_bytes()
            == fs::read(format!("{REPO}/{OWN}"))?
            && fs::read(format!("{REPO}/{OWN}"))?.as_slice()
                == include_bytes!("deploy_launch170retry8_v8.rs"),
        "helper source not published"
    );
    ensure!(
        sha(&fs::read(image)?) == image_sha && sha(&fs::read(test_image)?) == test_sha,
        "qualified artifact changed"
    );
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    for path in [
        Path::new(STATE).parent().context("state parent")?,
        Path::new(DEST).parent().context("runtime parent")?,
        Path::new(image),
        Path::new(test_image),
    ] {
        home_backed(path)?;
    }
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    home_backed(Path::new(STATE))?;
    let input_binding = save("qualification-inputs.json", &input_bytes)?;
    let production = bind(image)?;
    ensure!(
        production["sha256"] == image_sha,
        "production changed before capture"
    );
    let mut executions = serde_json::Map::new();
    let mut tests_passed = None;
    for phase in PHASES {
        let qualification = &inputs["qualifications"][phase];
        let unit = required_str(qualification, "unit")?;
        let expected_iid = required_str(qualification, "invocation_id")?;
        let raw = run(Command::new("/usr/bin/systemctl").args(["show", unit,
            "-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Environment"]))?;
        for required in [
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=exited",
            "MainPID=0",
            "ControlPID=0",
            "Result=success",
            "ExecMainStatus=0",
            "MemoryMax=2147483648",
            "MemorySwapMax=0",
            "CPUQuotaPerSecUSec=2s",
        ] {
            ensure!(
                raw.lines().any(|l| l == required),
                "{unit}: missing {required}"
            );
        }
        ensure!(
            raw.lines().any(|line| line == format!("Id={unit}")),
            "qualification unit differs"
        );
        let invocation = raw
            .lines()
            .find_map(|l| l.strip_prefix("InvocationID="))
            .context("native invocation")?;
        ensure!(
            invocation == expected_iid,
            "qualification invocation changed"
        );
        let command = raw
            .lines()
            .find_map(|l| l.strip_prefix("ExecStart="))
            .context("native command")?;
        if phase == "tests" {
            ensure!(
                command.contains(test_image)
                    && command.contains("--include-ignored")
                    && !command.contains("--skip")
                    && !command.contains("--exact"),
                "foreign or filtered test invocation"
            );
        } else {
            ensure!(
                command.contains(PACKAGE)
                    && command.contains(&format!("--target-dir {target}"))
                    && !command.contains("--features")
                    && command.contains("--release")
                    && command.contains("--locked")
                    && command.contains("--offline")
                    && command.contains("--jobs 2")
                    && !command.contains("--all-features"),
                "foreign build command"
            );
            ensure!(
                (phase == "test-build") == command.contains("--no-run"),
                "wrong build phase"
            );
            if phase == "clippy" {
                ensure!(command.contains("-D warnings"), "strict Clippy missing");
            }
            compile_environment(
                raw.lines()
                    .find_map(|line| line.strip_prefix("Environment="))
                    .context("compile environment")?,
                &inputs["compile_environment"],
            )?;
        }
        let native = save(&format!("{phase}-native.txt"), raw.as_bytes())?;
        let log = run(Command::new("/usr/bin/journalctl").args([
            "--no-pager",
            "--all",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
        ]))?;
        if phase == "tests" {
            tests_passed = Some(full_test_count(&log, expected_count)?);
        }
        let log_binding = save(&format!("{phase}.log"), log.as_bytes())?;
        let execution = json_file(
            &format!("{phase}.json"),
            &json!({"code":0,"unit":unit,
            "invocation_id":invocation,"native":native,"log":log_binding,"source_commit":commit.trim()}),
        )?;
        executions.insert(phase.into(), execution);
    }
    let mut source = Vec::new();
    let mut members = Vec::new();
    for path in git(&["ls-files", "--", PACKAGE])?.lines() {
        let name = path
            .strip_prefix(&format!("{PACKAGE}/"))
            .context("package member")?;
        ensure!(
            !name.contains("..") && !name.starts_with('/'),
            "unsafe source member"
        );
        let absolute = format!("{REPO}/{path}");
        let bytes = fs::read(&absolute)?;
        ensure!(
            git(&["show", &format!("{}:{path}", commit.trim())])?.as_bytes() == bytes,
            "unpublished source bytes"
        );
        let binding = json!({"path":absolute,"sha256":sha(&bytes)});
        members.push(member(
            &binding,
            &format!("source-{}", name.replace('/', "__")),
            0o444,
        )?);
        source.push(binding);
    }
    ensure!(
        source.len() == 8
            && source
                .iter()
                .any(|entry| entry["path"] == format!("{REPO}/{PACKAGE}/src/audit_budget.rs"))
            && bind(image)? == production
            && sha(&fs::read(test_image)?) == test_sha,
        "source incomplete or production changed"
    );
    let proof = json_file(
        "artifact-proof.json",
        &json!({"schema":"horizon-two-peer170-launcher-build-proof-v1",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "epoch":170,"attempt":"local3retry6",
        "runtime":{"path":format!("{DEST}/launch"),"sha256":production["sha256"]},
        "source_commit":commit.trim(),"equivalent_build_source_commit":build_commit,
        "source_contained_in_origin_account_updates":true,"source_members":source,
        "production":production,"test_image":{"path":test_image,"sha256":test_sha},
        "compile_environment":inputs["compile_environment"],"qualification_inputs":input_binding,
        "production_clippy_passed":true,"tests_passed":tests_passed.context("test result")?,"tests_failed":0,
        "executions":executions,"features":[],"resource_credit_bytes":0,"replay_launch_authorized":false,
        "remote_mutations":false,"genuine167_admission_and_operational_positive_test_still_required":true,
        "native_witness_and_fresh_admission_still_required":true}),
    )?;
    members.push(member(&production, "launch", 0o555)?);
    members.push(member(&input_binding, "qualification-inputs.json", 0o444)?);
    members.push(member(&proof, "artifact-proof.json", 0o444)?);
    let plan = json_file(
        "seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":DEST,"members":members}),
    )?;
    run(Command::new(SEALER).args([
        plan["path"].as_str().unwrap(),
        "--plan-sha256",
        plan["sha256"].as_str().unwrap(),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    home_backed(Path::new(DEST))?;
    println!(
        "{}",
        json!({"runtime":format!("{DEST}/launch"),"sha256":production["sha256"],
        "qualification":bind(&format!("{DEST}/artifact-proof.json"))?,"replay_launched":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings() -> Value {
        json!({
            "HORIZON_170_PREPARER_V5_SHA256":"a".repeat(64),
            "HORIZON_170_PREPARER_V5_PROOF_SHA256":"b".repeat(64),
            "HORIZON_170_PREPARER_V5_SOURCE_COMMIT":"c".repeat(40),
            "HORIZON_170_PREPARER_V5_TESTS_PASSED":"313"
        })
    }

    fn environment(bindings: &Value) -> String {
        BUILD_BINDINGS
            .iter()
            .map(|key| format!("{key}={}", bindings[*key].as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn compile_pins_reject_missing_changed_duplicate_and_unqualified_flags() {
        let bindings = bindings();
        let valid = environment(&bindings);
        compile_environment(&valid, &bindings).unwrap();
        let key = BUILD_BINDINGS[0];
        let value = bindings[key].as_str().unwrap();
        for bad in [
            valid.replace(&format!("{key}={value}"), ""),
            valid.replace(&format!("{key}={value}"), &format!("{key}=wrong")),
            format!("{valid} {key}={value}"),
            format!("{valid} RUSTFLAGS=-Awarnings"),
            format!("{valid} CARGO_ENCODED_RUSTFLAGS=-Awarnings"),
            valid.replace(
                "HORIZON_170_PREPARER_V5_TESTS_PASSED=313",
                "HORIZON_170_PREPARER_V5_TESTS_PASSED=3130",
            ),
        ] {
            assert!(compile_environment(&bad, &bindings).is_err());
        }
    }

    #[test]
    fn qualification_requires_one_complete_explicit_test_count() {
        let valid = "test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s";
        assert_eq!(full_test_count(valid, 20).unwrap(), 20);
        assert!(full_test_count(valid, 21).is_err());
        assert!(full_test_count(valid, 0).is_err());
        for bad in [
            valid.replace("20 passed", "18 passed"),
            valid.replace("0 failed", "1 failed"),
            valid.replace("0 ignored", "1 ignored"),
            valid.replace("0 filtered out", "1 filtered out"),
            format!("{valid}\n{valid}"),
            String::new(),
        ] {
            assert!(full_test_count(&bad, 20).is_err());
        }
    }

    #[test]
    fn qualification_inputs_require_all_actual_values_and_distinct_invocations() {
        let valid = json!({
            "schema":"horizon-epoch170-launcher-deployment-input-v8",
            "build_commit":"a".repeat(40),
            "target_directory":"/test/target",
            "production_image":{"path":"/test/target/release/horizon-retry6-single170-launch","sha256":"b".repeat(64)},
            "test_image":{"path":"/test/target/release/deps/horizon_retry6_single170_launch-1234567890abcdef","sha256":"c".repeat(64)},
            "expected_tests_passed":20,
            "compile_environment":bindings(),
            "qualifications":{
                "test-build":{"unit":"test-build.service","invocation_id":"a".repeat(32)},
                "production":{"unit":"production.service","invocation_id":"b".repeat(32)},
                "tests":{"unit":"tests.service","invocation_id":"c".repeat(32)},
                "clippy":{"unit":"clippy.service","invocation_id":"d".repeat(32)}
            }
        });
        validate_inputs(&valid).unwrap();
        for key in valid.as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(validate_inputs(&missing).is_err());
        }
        let mut changed = valid.clone();
        changed["qualifications"]["tests"]["invocation_id"] = json!("0".repeat(32));
        assert!(validate_inputs(&changed).is_err());
        changed["qualifications"]["tests"]["invocation_id"] = json!("a".repeat(32));
        assert!(validate_inputs(&changed).is_err());
        changed = valid.clone();
        changed["compile_environment"][BUILD_BINDINGS[0]] = json!("invented");
        assert!(validate_inputs(&changed).is_err());
        changed = valid;
        changed["production_image"]["path"] = json!("/foreign/launch");
        assert!(validate_inputs(&changed).is_err());
    }
}
