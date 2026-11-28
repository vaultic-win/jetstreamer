//! Preserve actual launcher qualification and seal the home-backed epoch170 v5 successor.
//! Does not book resources, capture a witness, change a service or start replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_170_guarded_launch_20261119_v1";
const STATE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/launch-v5-evidence";
const DEST: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/launch-v5";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/horizon-retry6-single170-launch";
const IMAGE_SHA: &str = "74cafe74769946f686c0fef3b3fa8064839c8deb4bf7009ec2ba3de9c7ac4a34";
const TEST_IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/deps/horizon_retry6_single170_launch-cb57035de23f1612";
const TEST_SHA: &str = "979d3199e398abc86074e1bd9af78edcab12d99eca76e2194807d0af1585eb8d";
const OWN: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_launch170retry8_v5.rs";
const BUILD_COMMIT: &str = "946ed00e45a5ed23626fa698154844e010e205a1";
const BUILD_BINDINGS: [(&str, &str); 4] = [
    (
        "HORIZON_170_PREPARER_V3_SHA256",
        "0b4e325aa56377455ceb33f955a0155e3c5753870e4a0ac60e625256a5547574",
    ),
    (
        "HORIZON_170_PREPARER_V3_PROOF_SHA256",
        "819de1a3970b0768b73123b041e2457fd866fd99a147b0aa986c97f40f6c5022",
    ),
    ("HORIZON_170_PREPARER_V3_SOURCE_COMMIT", BUILD_COMMIT),
    ("HORIZON_170_PREPARER_V3_TESTS_PASSED", "313"),
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
fn member(path: &str, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":sha(&fs::read(path)?),"mode":mode}))
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
fn compile_environment(environment: &str) -> Result<()> {
    ensure!(
        !environment.contains("RUSTFLAGS=") && !environment.contains("CARGO_ENCODED_RUSTFLAGS="),
        "unqualified Rust flags"
    );
    for (key, value) in BUILD_BINDINGS {
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
fn full_test_count(log: &str) -> Result<u64> {
    let summaries: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    ensure!(
        summaries.len() == 1,
        "one complete launcher test summary required"
    );
    let expected = "test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;";
    ensure!(
        summaries[0]
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(" finished in ")),
        "launcher tests incomplete"
    );
    Ok(20)
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "Root required; deploy_launch170retry8_v5 takes no arguments"
    );
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
        BUILD_COMMIT,
        "origin/account-updates",
    ])?;
    git(&["diff", "--exit-code", BUILD_COMMIT, "HEAD", "--", PACKAGE])?;
    ensure!(
        git(&["show", &format!("HEAD:{OWN}")])?.as_bytes() == fs::read(format!("{REPO}/{OWN}"))?
            && fs::read(format!("{REPO}/{OWN}"))?.as_slice()
                == include_bytes!("deploy_launch170retry8_v5.rs"),
        "helper source not published"
    );
    ensure!(
        sha(&fs::read(IMAGE)?) == IMAGE_SHA && sha(&fs::read(TEST_IMAGE)?) == TEST_SHA,
        "qualified artifact changed"
    );
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    for path in [
        Path::new(STATE).parent().context("state parent")?,
        Path::new(DEST).parent().context("runtime parent")?,
        Path::new(IMAGE),
        Path::new(TEST_IMAGE),
    ] {
        home_backed(path)?;
    }
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    home_backed(Path::new(STATE))?;
    let production = bind(IMAGE)?;
    let mut executions = serde_json::Map::new();
    let mut tests_passed = None;
    for (phase, version, expected_iid) in [
        (
            "test-build",
            "test-build",
            "9a999a9b86b84ca289be74a8cca46214",
        ),
        (
            "production",
            "production",
            "3beaac06498a448282ccc52f905db47b",
        ),
        ("tests", "native-tests", "d49330ac90504b078cbb87669373472f"),
        ("clippy", "clippy", "d7c21df8e14342ebb12e6f6c1ddaf4dc"),
    ] {
        let unit = format!("horizon-170-launcherv5-{version}-20261119-v1.service");
        let raw = run(Command::new("/usr/bin/systemctl").args(["show", &unit,
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
                command.contains(TEST_IMAGE)
                    && command.contains("--include-ignored")
                    && !command.contains("--skip")
                    && !command.contains("--exact"),
                "foreign or filtered test invocation"
            );
        } else {
            ensure!(
                command.contains(PACKAGE)
                    && !command.contains("--features")
                    && command.contains("--release")
                    && command.contains("--locked")
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
            tests_passed = Some(full_test_count(&log)?);
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
            git(&["show", &format!("HEAD:{path}")])?.as_bytes() == bytes,
            "unpublished source bytes"
        );
        source.push(bind(&absolute)?);
        members.push(member(
            &absolute,
            &format!("source-{}", name.replace('/', "__")),
            0o444,
        )?);
    }
    ensure!(
        source.len() == 8
            && source
                .iter()
                .any(|entry| entry["path"] == format!("{REPO}/{PACKAGE}/src/audit_budget.rs"))
            && bind(IMAGE)? == production
            && sha(&fs::read(TEST_IMAGE)?) == TEST_SHA,
        "source incomplete or production changed"
    );
    let proof = json_file(
        "artifact-proof.json",
        &json!({"schema":"horizon-two-peer170-launcher-build-proof-v1",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "epoch":170,"attempt":"local3retry6",
        "runtime":{"path":format!("{DEST}/launch"),"sha256":production["sha256"]},
        "source_commit":commit.trim(),"equivalent_build_source_commit":BUILD_COMMIT,
        "source_contained_in_origin_account_updates":true,"source_members":source,
        "production":production,"test_image":{"path":TEST_IMAGE,"sha256":TEST_SHA},
        "compile_environment":BUILD_BINDINGS.into_iter().map(|(key,value)| (key.to_owned(),json!(value))).collect::<serde_json::Map<String, Value>>(),
        "production_clippy_passed":true,"tests_passed":tests_passed.context("test result")?,"tests_failed":0,
        "executions":executions,"features":[],"resource_credit_bytes":0,"replay_launch_authorized":false,
        "remote_mutations":false,"genuine167_admission_and_operational_positive_test_still_required":true,
        "native_witness_and_fresh_admission_still_required":true}),
    )?;
    members.push(member(IMAGE, "launch", 0o555)?);
    members.push(member(
        proof["path"].as_str().unwrap(),
        "artifact-proof.json",
        0o444,
    )?);
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

    fn environment() -> String {
        BUILD_BINDINGS
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn compile_pins_reject_missing_changed_duplicate_and_unqualified_flags() {
        let valid = environment();
        compile_environment(&valid).unwrap();
        let (key, value) = BUILD_BINDINGS[0];
        for bad in [
            valid.replace(&format!("{key}={value}"), ""),
            valid.replace(&format!("{key}={value}"), &format!("{key}=wrong")),
            format!("{valid} {key}={value}"),
            format!("{valid} RUSTFLAGS=-Awarnings"),
            format!("{valid} CARGO_ENCODED_RUSTFLAGS=-Awarnings"),
            valid.replace(
                "HORIZON_170_PREPARER_V3_TESTS_PASSED=313",
                "HORIZON_170_PREPARER_V3_TESTS_PASSED=3130",
            ),
        ] {
            assert!(compile_environment(&bad).is_err());
        }
    }

    #[test]
    fn qualification_requires_one_complete_twenty_test_summary() {
        let valid = "test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s";
        assert_eq!(full_test_count(valid).unwrap(), 20);
        for bad in [
            valid.replace("20 passed", "18 passed"),
            valid.replace("0 failed", "1 failed"),
            valid.replace("0 ignored", "1 ignored"),
            valid.replace("0 filtered out", "1 filtered out"),
            format!("{valid}\n{valid}"),
            String::new(),
        ] {
            assert!(full_test_count(&bad).is_err());
        }
    }
}
