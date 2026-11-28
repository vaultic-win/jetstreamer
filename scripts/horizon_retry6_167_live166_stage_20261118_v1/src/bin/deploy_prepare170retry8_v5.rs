//! Preserve genuine preparer qualification and seal the epoch170 HOME-contract successor.
//! Usage: deploy_prepare170retry8_v5 /absolute/path/to/qualification-inputs.json
//! All artifact, build-commit, test-count and native invocation inputs are mandatory.
//! Does not book resources, capture a witness, change a service or start replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Component, Path},
    process::Command,
};

const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_170_20261118_v1/prepare-live166retry8-v1";
const AUDIT_SOURCE: &str =
    "scripts/horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs";
const OWN_SOURCE: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_prepare170retry8_v5.rs";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/prepare-v5-evidence";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/prepare-v5";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const PHASES: [&str; 4] = ["test-build", "tests", "production-build", "clippy"];

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_regular(path: &str) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "not a regular file: {path}");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn run(command: &mut Command) -> Result<String> {
    let result = command.output()?;
    ensure!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn git(args: &[&str]) -> Result<String> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(args))
}
fn bind(path: &str) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&read_regular(path)?)}))
}
fn save(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(
        !name.is_empty() && !name.contains('/') && name != "." && name != "..",
        "leaf required"
    );
    let path = format!("{STATE}/{name}");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
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
        sha(&read_regular(path)?) == expected,
        "bound member changed: {path}"
    );
    Ok(json!({"source":path,"name":name,"sha256":expected,"mode":mode}))
}
fn published_source(path: &str, commit: &str) -> Result<Value> {
    let absolute = format!("{REPO}/{path}");
    let bytes = read_regular(&absolute)?;
    ensure!(
        git(&["show", &format!("{commit}:{path}")])?.as_bytes() == bytes,
        "unpublished source bytes: {path}"
    );
    Ok(json!({"path":absolute,"sha256":sha(&bytes)}))
}
fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("expected object")?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "required fields are exactly {keys:?}"
    );
    Ok(())
}
fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("missing nonempty string: {key}"))
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
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            })
            && !value.contains("//")
            && !value.ends_with('/'),
        "absolute, unambiguous path required: {value}"
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
            "qualifications",
        ],
    )?;
    ensure!(
        inputs["schema"] == "horizon-epoch170-preparer-deployment-input-v5",
        "wrong input schema"
    );
    ensure!(
        lower_hex(required_str(inputs, "build_commit")?, 40),
        "full build commit required"
    );
    let target = required_str(inputs, "target_directory")?;
    absolute_path(target)?;
    for key in ["production_image", "test_image"] {
        exact_keys(&inputs[key], &["path", "sha256"])?;
        absolute_path(required_str(&inputs[key], "path")?)?;
        ensure!(
            lower_hex(required_str(&inputs[key], "sha256")?, 64),
            "actual {key} SHA-256 required"
        );
    }
    ensure!(
        inputs["production_image"]["path"] == format!("{target}/release/prepare"),
        "production image does not belong to declared target"
    );
    let test_name = required_str(&inputs["test_image"], "path")?
        .strip_prefix(&format!("{target}/release/deps/prepare-"))
        .context("test image does not belong to declared target")?;
    ensure!(lower_hex(test_name, 16), "unexpected Cargo test image name");
    ensure!(
        inputs["expected_tests_passed"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "actual positive full-suite test count required"
    );
    exact_keys(&inputs["qualifications"], &PHASES)?;
    let mut units = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for phase in PHASES {
        let qualification = &inputs["qualifications"][phase];
        exact_keys(qualification, &["unit", "invocation_id"])?;
        let unit = required_str(qualification, "unit")?;
        ensure!(
            unit.ends_with(".service")
                && unit.len() > ".service".len()
                && unit.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                })
                && units.insert(unit),
            "distinct explicit qualification service required"
        );
        let invocation = required_str(qualification, "invocation_id")?;
        ensure!(
            lower_hex(invocation, 32) && invocations.insert(invocation),
            "four distinct genuine invocation IDs required"
        );
    }
    Ok(())
}
fn property<'a>(native: &'a str, key: &str) -> Result<&'a str> {
    let prefix = format!("{key}=");
    let values: Vec<_> = native
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    ensure!(values.len() == 1, "missing or duplicate native {key}");
    Ok(values[0])
}
fn validate_native(native: &str, phase: &str, inputs: &Value) -> Result<()> {
    let qualification = &inputs["qualifications"][phase];
    ensure!(
        property(native, "Id")? == required_str(qualification, "unit")?,
        "native unit identity changed"
    );
    for (key, value) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
    ] {
        ensure!(property(native, key)? == value, "native {key} != {value}");
    }
    ensure!(
        property(native, "InvocationID")? == required_str(qualification, "invocation_id")?,
        "qualification invocation changed"
    );
    let command = property(native, "ExecStart")?;
    let argv = command
        .strip_prefix("{ path=")
        .and_then(|value| value.split_once(" ; argv[]=").map(|(_, argv)| argv))
        .and_then(|value| value.split_once(" ; ignore_errors=").map(|(argv, _)| argv))
        .context("unrecognized native command format")?;
    ensure!(
        !argv.contains(['\\', '\'', '"']) && command.matches("argv[]=").count() == 1,
        "ambiguous native command"
    );
    let words: Vec<_> = argv.split_whitespace().collect();
    let has_pair = |first: &str, second: &str| words.windows(2).any(|pair| pair == [first, second]);
    let has_path_pair = |flag: &str, absolute: &str| {
        has_pair(flag, absolute)
            || (matches!(property(native, "WorkingDirectory"), Ok(REPO))
                && absolute
                    .strip_prefix(&format!("{REPO}/"))
                    .is_some_and(|relative| has_pair(flag, relative)))
    };
    if phase == "tests" {
        ensure!(
            words.first().copied() == Some(required_str(&inputs["test_image"], "path")?)
                && !argv.contains("--skip")
                && !argv.contains("--ignored")
                && !argv.contains("--exact"),
            "foreign or filtered test image"
        );
    } else {
        ensure!(
            has_path_pair("--manifest-path", &format!("{REPO}/{PACKAGE}/Cargo.toml"))
                && has_pair("--bin", "prepare")
                && has_path_pair("--target-dir", required_str(inputs, "target_directory")?)
                && has_pair("--features", "preparation")
                && words.contains(&"--release")
                && words.contains(&"--locked")
                && words.contains(&"--offline")
                && has_pair("--jobs", "2")
                && !words.contains(&"--all-features")
                && !words.contains(&"--no-default-features"),
            "foreign build command or incomplete qualification flags"
        );
        ensure!(
            (phase == "test-build") == words.contains(&"--no-run"),
            "wrong compile phase"
        );
        let subcommand = match phase {
            "test-build" => "test",
            "production-build" => "build",
            "clippy" => "clippy",
            _ => anyhow::bail!("unknown qualification phase"),
        };
        let cargo_name = words
            .first()
            .and_then(|word| Path::new(word).file_name())
            .and_then(|name| name.to_str());
        ensure!(
            cargo_name == Some("cargo"),
            "qualification must run Cargo directly"
        );
        let command_index = if words.get(1).is_some_and(|word| word.starts_with('+')) {
            2
        } else {
            1
        };
        ensure!(
            words.get(command_index).copied() == Some(subcommand),
            "wrong Cargo qualification subcommand"
        );
        if phase == "clippy" {
            ensure!(has_pair("-D", "warnings"), "strict Clippy missing");
        }
        let environment = property(native, "Environment")?;
        ensure!(
            !environment.contains("RUSTFLAGS=")
                && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
            "unqualified rust flags"
        );
    }
    Ok(())
}
fn full_test_count(log: &str, expected: u64) -> Result<u64> {
    let summaries: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    ensure!(summaries.len() == 1, "one full-suite test summary required");
    let required = format!(
        "test result: ok. {expected} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
    );
    ensure!(
        expected > 0
            && summaries[0]
                .strip_prefix(&required)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(" finished in ")),
        "preparer tests incomplete"
    );
    Ok(expected)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 2,
        "Root required; deploy_prepare170retry8_v5 /absolute/path/to/qualification-inputs.json"
    );
    absolute_path(&args[1])?;
    let input_bytes = read_regular(&args[1])?;
    let inputs: Value = serde_json::from_slice(&input_bytes)?;
    validate_inputs(&inputs)?;
    let build_commit = required_str(&inputs, "build_commit")?;
    let image = required_str(&inputs["production_image"], "path")?;
    let image_sha = required_str(&inputs["production_image"], "sha256")?;
    let test_image = required_str(&inputs["test_image"], "path")?;
    let test_sha = required_str(&inputs["test_image"], "sha256")?;
    let expected_tests = inputs["expected_tests_passed"]
        .as_u64()
        .context("expected test count")?;
    let commit = git(&["rev-parse", "HEAD"])?;
    for required in [commit.trim(), build_commit] {
        git(&[
            "merge-base",
            "--is-ancestor",
            required,
            "origin/account-updates",
        ])?;
    }
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            PACKAGE,
            AUDIT_SOURCE,
            OWN_SOURCE,
        ])?
        .is_empty(),
        "published source closure changed"
    );
    git(&[
        "diff",
        "--exit-code",
        build_commit,
        commit.trim(),
        "--",
        PACKAGE,
        AUDIT_SOURCE,
    ])?;
    let helper = published_source(OWN_SOURCE, commit.trim())?;
    ensure!(
        sha(&read_regular(image)?) == image_sha && sha(&read_regular(test_image)?) == test_sha,
        "qualified artifact changed"
    );
    ensure!(sha(&read_regular(SEALER)?) == SEALER_SHA, "sealer changed");
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    File::open(Path::new(STATE).parent().context("evidence parent")?)?.sync_all()?;
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
        let invocation = required_str(qualification, "invocation_id")?;
        let native_text = run(Command::new("/usr/bin/systemctl").args(["show", unit,
            "-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Environment,WorkingDirectory"]))?;
        validate_native(&native_text, phase, &inputs)
            .with_context(|| format!("qualification phase {phase}, unit {unit}"))?;
        let native = save(&format!("{phase}-native.txt"), native_text.as_bytes())?;
        let log = run(Command::new("/usr/bin/journalctl").args([
            "--no-pager",
            "--all",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
        ]))?;
        if phase == "tests" {
            tests_passed = Some(full_test_count(&log, expected_tests)?);
        }
        let log_binding = save(&format!("{phase}.log"), log.as_bytes())?;
        let execution = json_file(
            &format!("{phase}.json"),
            &json!({"code":0,"unit":unit,"invocation_id":invocation,
                "native":native,"log":log_binding,"source_commit":commit.trim(),
                "equivalent_build_source_commit":build_commit}),
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
            !name.contains('/') && name != "audit_budget.rs" && name != "deployment-helper.rs",
            "unexpected or colliding source member"
        );
        let binding = published_source(path, commit.trim())?;
        members.push(member(&binding, &format!("source-{name}"), 0o444)?);
        source.push(binding);
    }
    ensure!(source.len() >= 40, "package source incomplete");
    let audit_source = published_source(AUDIT_SOURCE, commit.trim())?;
    members.push(member(&audit_source, "source-audit_budget.rs", 0o444)?);
    source.push(audit_source);
    members.push(member(&helper, "source-deployment-helper.rs", 0o444)?);
    ensure!(
        bind(image)? == production && sha(&read_regular(test_image)?) == test_sha,
        "qualified artifacts changed during evidence capture"
    );
    let proof = json_file(
        "artifact-proof.json",
        &json!({"schema":"horizon-live166retry8-preparer-build-proof-v1",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "epoch":170,"attempt":"local3retry6","deployment_generation":"prepare-v5",
        "runtime":{"path":format!("{DEST}/prepare"),"sha256":production["sha256"]},
        "source_commit":commit.trim(),"equivalent_build_source_commit":build_commit,
        "source_contained_in_origin_account_updates":true,"source_commit_verified_on_origin_account_updates":true,
        "source_members":source,"deployment_helper_source":helper,"qualification_inputs":input_binding,
        "production":production,"test_image":{"path":test_image,"sha256":test_sha},
        "production_clippy_passed":true,"tests_passed":tests_passed.context("test result")?,"tests_failed":0,
        "executions":executions,"features":["preparation"],"offline_locked_release":true,
        "resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false,
        "genuine167_admission_and_operational_positive_test_still_required":true,
        "native_witness_and_fresh_admission_still_required":true,"guard_unchanged":true,
        "exact_guard_equivalence_proof_still_required":true}),
    )?;
    members.push(member(&production, "prepare", 0o555)?);
    for (binding, name) in [
        (&proof, "artifact-proof.json"),
        (&input_binding, "qualification-inputs.json"),
    ] {
        members.push(member(binding, name, 0o444)?);
    }
    let plan = json_file(
        "seal-plan.json",
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1",
        "destination":DEST,"members":members}),
    )?;
    run(Command::new(SEALER).args([
        plan["path"].as_str().context("plan path")?,
        "--plan-sha256",
        plan["sha256"].as_str().context("plan digest")?,
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    println!(
        "{}",
        json!({"runtime":format!("{DEST}/prepare"),"sha256":production["sha256"],
        "qualification":bind(&format!("{DEST}/artifact-proof.json"))?,"replay_launched":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Value {
        json!({
            "schema":"horizon-epoch170-preparer-deployment-input-v5",
            "build_commit":"a".repeat(40),
            "target_directory":"/test/target",
            "production_image":{"path":"/test/target/release/prepare","sha256":"b".repeat(64)},
            "test_image":{"path":"/test/target/release/deps/prepare-1234567890abcdef","sha256":"c".repeat(64)},
            "expected_tests_passed":311,
            "qualifications":{
                "test-build":{"unit":"test-build.service","invocation_id":"a".repeat(32)},
                "tests":{"unit":"tests.service","invocation_id":"b".repeat(32)},
                "production-build":{"unit":"production-build.service","invocation_id":"c".repeat(32)},
                "clippy":{"unit":"clippy.service","invocation_id":"d".repeat(32)}
            }
        })
    }

    #[test]
    fn rejects_missing_inputs_and_placeholder_identities() {
        assert!(validate_inputs(&json!({})).is_err());
        assert!(!lower_hex(&"0".repeat(32), 32));
        assert!(!lower_hex("GenuineInvocationRequired", 32));
        let valid = inputs();
        validate_inputs(&valid).unwrap();
        for key in valid.as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(validate_inputs(&missing).is_err(), "missing {key}");
        }
        let mut reused = valid.clone();
        reused["qualifications"]["tests"]["invocation_id"] =
            reused["qualifications"]["test-build"]["invocation_id"].clone();
        assert!(validate_inputs(&reused).is_err());
        let mut foreign = valid;
        foreign["production_image"]["path"] = json!("/foreign/release/prepare");
        assert!(validate_inputs(&foreign).is_err());
    }

    #[test]
    fn native_build_requires_genuine_identity_resource_envelope_and_offline_flags() {
        let inputs = inputs();
        let native = format!(
            "Id=test-build.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nMainPID=0\nControlPID=0\nResult=success\nExecMainStatus=0\nMemoryMax=2147483648\nMemorySwapMax=0\nCPUQuotaPerSecUSec=2s\nInvocationID={}\nEnvironment=\nExecStart={{ path=/test/cargo ; argv[]=/test/cargo test --manifest-path {REPO}/{PACKAGE}/Cargo.toml --bin prepare --target-dir /test/target --features preparation --release --locked --offline --jobs 2 --no-run ; ignore_errors=no ; code=exited ; status=0 }}\n",
            "a".repeat(32)
        );
        validate_native(&native, "test-build", &inputs).unwrap();
        let relative = format!(
            "WorkingDirectory={REPO}\n{}",
            native.replace(&format!("--manifest-path {REPO}/"), "--manifest-path ")
        );
        validate_native(&relative, "test-build", &inputs).unwrap();
        assert!(
            validate_native(
                &relative.replace(
                    &format!("WorkingDirectory={REPO}"),
                    "WorkingDirectory=/foreign"
                ),
                "test-build",
                &inputs
            )
            .is_err()
        );
        for (from, to) in [
            ("--offline", ""),
            ("--no-run", ""),
            ("MemoryMax=2147483648", "MemoryMax=infinity"),
            ("CPUQuotaPerSecUSec=2s", "CPUQuotaPerSecUSec=4s"),
            ("ExecMainStatus=0", "ExecMainStatus=1"),
            ("Id=test-build.service", "Id=foreign.service"),
            ("Environment=", "Environment=RUSTFLAGS=-Adead_code"),
            ("--features preparation", "--features preparation,extra"),
        ] {
            assert!(
                validate_native(&native.replace(from, to), "test-build", &inputs).is_err(),
                "native mutation accepted: {from} -> {to}"
            );
        }
        assert!(
            validate_native(
                &native.replace(&"a".repeat(32), &"e".repeat(32)),
                "test-build",
                &inputs
            )
            .is_err()
        );
    }

    #[test]
    fn full_suite_requires_exact_positive_count_and_no_filtered_or_ignored_tests() {
        let summary = "test result: ok. 311 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.23s";
        assert_eq!(full_test_count(summary, 311).unwrap(), 311);
        assert!(full_test_count(summary, 310).is_err());
        assert!(full_test_count(&summary.replace("0 filtered", "1 filtered"), 311).is_err());
        assert!(full_test_count(&summary.replace("0 ignored", "1 ignored"), 311).is_err());
        assert!(full_test_count(&format!("{summary}\n{summary}"), 311).is_err());
        assert!(
            full_test_count(
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                0
            )
            .is_err()
        );
    }
}
