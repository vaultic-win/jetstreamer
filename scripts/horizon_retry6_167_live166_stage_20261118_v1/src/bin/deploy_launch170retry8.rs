//! Preserve actual launcher qualification and seal the exact epoch170 successor.
//! Does not book resources, capture a witness, change a service or start replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_170_guarded_launch_20261119_v1";
const STATE: &str =
    "/var/lib/jetstreamer/epoch170-retry6-live166retry8-guarded-launch-deployment-20261119-v1";
const DEST: &str =
    "/usr/local/lib/jetstreamer/horizon-retry6-single170-launch-live166retry8-20261119-v1";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/horizon-retry6-single170-launch";
const IMAGE_SHA: &str = "42e329468f74b193cf9401f8a0a4826f78112e51ea34fee95f221be3ce8a3d98";
const TEST_IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/deps/horizon_retry6_single170_launch-cb57035de23f1612";
const TEST_SHA: &str = "853d187f2155a7dce8e3f7cac7d25fecc0d3878fae05ebd4965f64509e2b4bd1";
const OWN: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_launch170retry8.rs";
const BUILD_COMMIT: &str = "1240da34352a348d9830500c6adceab218e2bbfa";
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
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "Root required; deploy_launch170retry8 takes no arguments"
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
        git(&["show", &format!("HEAD:{OWN}")])?.as_bytes() == fs::read(format!("{REPO}/{OWN}"))?,
        "helper source not published"
    );
    ensure!(
        sha(&fs::read(IMAGE)?) == IMAGE_SHA && sha(&fs::read(TEST_IMAGE)?) == TEST_SHA,
        "qualified artifact changed"
    );
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    let production = bind(IMAGE)?;
    let mut executions = serde_json::Map::new();
    let mut tests_passed = None;
    for (phase, version, expected_iid) in [
        ("test-build", "v2", "c068a398429a4724ae131892e39b84c1"),
        ("production", "v1", "1bfdd9aaa1b74f0e9b81f0da5010f45f"),
        ("tests", "v2", "0e5db3000270482aa3413933859fbfd2"),
        ("clippy", "v2", "254a651223b44f4a921464393ee56463"),
    ] {
        let unit = format!("horizon-launch170retry8-{phase}-20261119-{version}.service");
        let raw = run(Command::new("/usr/bin/systemctl").args(["show", &unit,
            "-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,CPUQuotaPerSecUSec,MemoryMax,TasksMax,Environment"]))?;
        for required in [
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=exited",
            "MainPID=0",
            "ControlPID=0",
            "Result=success",
            "ExecMainStatus=0",
            "MemoryMax=2147483648",
            "CPUQuotaPerSecUSec=2s",
        ] {
            ensure!(
                raw.lines().any(|l| l == required),
                "{unit}: missing {required}"
            );
        }
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
            let line = log
                .lines()
                .find(|l| l.starts_with("test result: ok. "))
                .context("successful test summary")?;
            let count = line
                .strip_prefix("test result: ok. ")
                .unwrap()
                .split_whitespace()
                .next()
                .context("test count")?
                .parse::<u64>()?;
            ensure!(
                count == 14 && line.contains("0 failed; 0 ignored; 0 measured; 0 filtered out;"),
                "launcher tests incomplete"
            );
            tests_passed = Some(count);
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
        source.len() == 8 && bind(IMAGE)? == production && sha(&fs::read(TEST_IMAGE)?) == TEST_SHA,
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
    println!(
        "{}",
        json!({"runtime":format!("{DEST}/launch"),"sha256":production["sha256"],
        "qualification":bind(&format!("{DEST}/artifact-proof.json"))?,"replay_launched":false})
    );
    Ok(())
}
