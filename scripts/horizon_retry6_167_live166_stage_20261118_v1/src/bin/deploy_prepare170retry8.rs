//! Preserve actual preparer qualification and seal the exact epoch170 successor.
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
const PACKAGE: &str = "scripts/horizon_retry6_170_20261118_v1/prepare-live166retry8-v1";
const STATE: &str =
    "/var/lib/jetstreamer/epoch170-retry6-live166retry8-prepare-deployment-20261119-v1";
const DEST: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-prepare-20261119-v1";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/prepare";
const IMAGE_SHA: &str = "f33a100bd73c75cb1c1d5f000ab81abdc3fba71040cc72b2949ffd320cae9632";
const TEST_IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/deps/prepare-40bd154e8d0f598f";
const TEST_SHA: &str = "56e42b3d8655d072c2449d48cf6a4e9e92358403a897cbb93c90fa7f4aff5f59";
const OWN_SOURCE: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_prepare170retry8.rs";
const BUILD_COMMIT: &str = "60ef954d8c1665a0f259cde34ba9fc46a5683d1a";
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
        "Root required; deploy_prepare170retry8 takes no arguments"
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
            OWN_SOURCE
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
        git(&["show", &format!("HEAD:{OWN_SOURCE}")])?.as_bytes()
            == fs::read(format!("{REPO}/{OWN_SOURCE}"))?,
        "deployment helper source not published"
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
    for (phase, expected_iid) in [
        ("test-build", "c8f1c8d8da8447f7a6a9975a1fd95d52"),
        ("tests", "6d2399398cdb4808a8fb70be7e07c563"),
        ("production-build", "d42f6283217c45f1877bb4a7a83780d3"),
        ("clippy", "c03f99c86a464dbd85cf1f3daad07ecb"),
    ] {
        let unit = format!("horizon-retry6-170-live166retry8-{phase}-20261119-v2.service");
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
                    && !command.contains("--skip")
                    && !command.contains("--ignored")
                    && !command.contains("--exact"),
                "foreign or filtered test image"
            );
        } else {
            ensure!(
                command.contains(PACKAGE)
                    && command.contains("--bin prepare")
                    && command.contains("scripts/horizon_retry8_166_20261119_v1/guard/target")
                    && command.contains("--features preparation")
                    && command.contains("--release")
                    && command.contains("--locked")
                    && command.contains("--jobs 2")
                    && !command.contains("--all-features"),
                "foreign build command"
            );
            ensure!(
                (phase == "test-build") == command.contains("--no-run"),
                "wrong compile phase"
            );
            if phase == "clippy" {
                ensure!(command.contains("-D warnings"), "strict Clippy missing");
            }
            let env = raw
                .lines()
                .find_map(|l| l.strip_prefix("Environment="))
                .context("build environment")?;
            ensure!(
                !env.contains("RUSTFLAGS=") && !env.contains("CARGO_ENCODED_RUSTFLAGS="),
                "unqualified rust flags"
            );
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
                count == 305 && line.contains("0 failed; 0 ignored; 0 measured; 0 filtered out;"),
                "preparer tests incomplete"
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
        ensure!(!name.contains('/'), "unexpected nested source member");
        let absolute = format!("{REPO}/{path}");
        let bytes = fs::read(&absolute)?;
        ensure!(
            git(&["show", &format!("HEAD:{path}")])?.as_bytes() == bytes,
            "unpublished source bytes"
        );
        source.push(bind(&absolute)?);
        members.push(member(&absolute, &format!("source-{name}"), 0o444)?);
    }
    ensure!(
        source.len() >= 40 && bind(IMAGE)? == production && sha(&fs::read(TEST_IMAGE)?) == TEST_SHA,
        "source incomplete or production changed"
    );
    let proof = json_file(
        "artifact-proof.json",
        &json!({"schema":"horizon-live166retry8-preparer-build-proof-v1",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "epoch":170,"attempt":"local3retry6",
        "runtime":{"path":format!("{DEST}/prepare"),"sha256":production["sha256"]},
        "source_commit":commit.trim(),"equivalent_build_source_commit":BUILD_COMMIT,
        "source_contained_in_origin_account_updates":true,"source_commit_verified_on_origin_account_updates":true,"source_members":source,
        "production":production,"test_image":{"path":TEST_IMAGE,"sha256":TEST_SHA},"production_clippy_passed":true,"tests_passed":tests_passed.context("test result")?,"tests_failed":0,
        "executions":executions,"features":["preparation"],"resource_credit_bytes":0,"replay_launch_authorized":false,
        "remote_mutations":false,"genuine167_admission_and_operational_positive_test_still_required":true,
        "native_witness_and_fresh_admission_still_required":true,"guard_unchanged":true,"exact_guard_equivalence_proof_still_required":true}),
    )?;
    members.push(member(IMAGE, "prepare", 0o555)?);
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
        json!({"runtime":format!("{DEST}/prepare"),"sha256":production["sha256"],
        "qualification":bind(&format!("{DEST}/artifact-proof.json"))?,"replay_launched":false})
    );
    Ok(())
}
