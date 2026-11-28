//! Preserve actual launcher qualification and seal the exact epoch167 successor.
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
const PACKAGE: &str = "scripts/horizon_retry6_167_guarded_launch_20261118_v1";
const STATE: &str = "/var/lib/jetstreamer/epoch167-retry6-guarded-launch-deployment-20261119-v2";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-retry6-single167-launch-20261119-v2";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry6_167_guarded_launch_20261118_v1/target/release/horizon-retry6-single167-launch";
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
    run(Command::new("git").arg("-C").arg(REPO).args(args))
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
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 2
            && args[1].len() == 40
            && args[1].bytes().all(|b| b.is_ascii_hexdigit()),
        "Root required; deploy_launch167v2 BUILD_COMMIT"
    );
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    ensure!(
        git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        "tracked tree changed"
    );
    git(&[
        "merge-base",
        "--is-ancestor",
        &args[1],
        "origin/account-updates",
    ])?;
    git(&["diff", "--exit-code", &args[1], "HEAD", "--", PACKAGE])?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    fs::DirBuilder::new().mode(0o700).create(STATE)?;
    let production = bind(IMAGE)?;
    let mut executions = serde_json::Map::new();
    let mut tests_passed = None;
    for (phase, expected_iid) in [
        ("production", "fc94df6d8d1440adba607bbfa56dee36"),
        ("tests", "9f7ce7960cc54d6582e296057b366846"),
        ("clippy", "8356bc91f65f499a8ca6c41083dc206b"),
    ] {
        let unit = format!("horizon-single167-launch-v2-{phase}-20261119-v1.service");
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
        ensure!(
            command.contains(PACKAGE)
                && !command.contains("--features")
                && command.contains("--release --locked --jobs 2")
                && !command.contains("--all-features"),
            "foreign build command"
        );
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
                count == 9 && line.contains("0 failed; 0 ignored; 0 measured; 0 filtered out;"),
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
        source.len() == 4 && bind(IMAGE)? == production,
        "source incomplete or production changed"
    );
    let proof = json_file(
        "artifact-proof.json",
        &json!({"schema":"horizon-single167-launcher-build-proof-v2",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "epoch":167,"attempt":"local3retry6",
        "runtime":{"path":format!("{DEST}/launch"),"sha256":production["sha256"]},
        "source_commit":commit.trim(),"equivalent_build_source_commit":args[1],
        "source_contained_in_origin_account_updates":true,"source_members":source,
        "production":production,"production_clippy_passed":true,"tests_passed":tests_passed.context("test result")?,"tests_failed":0,
        "executions":executions,"features":[],"resource_credit_bytes":0,"replay_launch_authorized":false,
        "remote_mutations":false,"operational_check_and_fresh_admission_still_required":true,
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
