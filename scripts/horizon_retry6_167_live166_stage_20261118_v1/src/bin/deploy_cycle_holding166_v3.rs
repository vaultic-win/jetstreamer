//! Seal the qualified cycle helper; no replay or R2 authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";
const STATE: &str = "/var/lib/jetstreamer/cycle-holding166-deployment-20261119-v3";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-observe-retry8-with167-20261119-v3";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/observe_cycle_retry8";
const IMAGE_SHA: &str = "1f5964b9e8c1234ac0818f3fe9e2c73962ee94dc001e8f7cd434bcbf30a7a77b";
const SOURCE_SHA: &str = "f157c425b0a26ff321871ae52013fea27a74ee5e92005f9f4202b517c551cf10";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn command(program: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(program).args(args).output()?;
    ensure!(
        o.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn git(args: &[&str]) -> Result<String> {
    let mut a = vec![
        "-c",
        "safe.directory=/home/sol/workspace/jetstreamer",
        "-C",
        REPO,
    ];
    a.extend_from_slice(args);
    command("/usr/bin/git", &a)
}
fn save(name: &str, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(format!("{STATE}/{name}"))?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(STATE)?.sync_all()?;
    Ok(())
}
fn member(path: &str, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"mode":mode,"sha256":sha(&fs::read(path)?)}))
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "root; no arguments"
    );
    ensure!(
        sha(&fs::read(IMAGE)?) == IMAGE_SHA && sha(&fs::read(SEALER)?) == SEALER_SHA,
        "image mismatch"
    );
    let commit = git(&["rev-parse", "HEAD"])?;
    git(&[
        "merge-base",
        "--is-ancestor",
        commit.trim(),
        "origin/account-updates",
    ])?;
    let mut members = vec![member(IMAGE, "cycle", 0o555)?];
    let mut sources = serde_json::Map::new();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "src/bin/observe_cycle_retry8.rs",
        "src/bin/deploy_cycle_holding166_v3.rs",
    ] {
        let relative = format!("{PACKAGE}/{name}");
        let path = format!("{REPO}/{relative}");
        let bytes = fs::read(&path)?;
        ensure!(
            git(&["show", &format!("HEAD:{relative}")])?.as_bytes() == bytes,
            "unpublished source"
        );
        if name.ends_with("/observe_cycle_retry8.rs") {
            ensure!(sha(&bytes) == SOURCE_SHA, "source changed since build");
        }
        sources.insert(relative, json!(sha(&bytes)));
        members.push(member(
            &path,
            Path::new(name)
                .file_name()
                .context("source name")?
                .to_str()
                .context("UTF8")?,
            0o444,
        )?);
    }
    let mut executions = serde_json::Map::new();
    for (phase, unit, iid) in [
        (
            "tests",
            "horizon-cycle-holding166-tests-20261119-v1.service",
            "265f14c92ed64dabbdfc4151e2871d76",
        ),
        (
            "clippy",
            "horizon-cycle-holding166-clippy-20261119-v2.service",
            "31c98973a0724111bc626ad6c23246c7",
        ),
        (
            "production",
            "horizon-cycle-holding166-production-20261119-v1.service",
            "b01982a6138b42e2bf6c393f7c5a85ac",
        ),
    ] {
        let native = if phase == "tests" {
            fs::read_to_string(format!("{STATE}/tests-native.txt"))?
        } else {
            command(
                "/usr/bin/systemctl",
                &[
                    "show",
                    unit,
                    "-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,Result,ExecMainStatus,ExecStart,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax",
                ],
            )?
        };
        for field in [
            format!("Id={unit}"),
            format!("InvocationID={iid}"),
            "ActiveState=active".into(),
            "SubState=exited".into(),
            "MainPID=0".into(),
            "ControlPID=0".into(),
            "Result=success".into(),
            "ExecMainStatus=0".into(),
            "CPUQuotaPerSecUSec=2s".into(),
            "MemoryMax=2147483648".into(),
            "MemorySwapMax=0".into(),
        ] {
            ensure!(native.lines().any(|l| l == field), "missing {field}");
        }
        ensure!(
            native.contains("--bin observe_cycle_retry8")
                && native.contains("--locked")
                && native.contains("--offline"),
            "foreign command"
        );
        let log = command(
            "/usr/bin/journalctl",
            &[
                "--no-pager",
                "--all",
                "-o",
                "cat",
                &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            ],
        )?;
        if phase == "tests" {
            ensure!(
                log.contains(
                    "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
                ),
                "test proof missing"
            );
        }
        if phase == "clippy" {
            ensure!(native.contains("-D warnings"), "strict clippy missing");
        }
        for (name, bytes) in [
            (format!("{phase}-captured-native.txt"), native.as_bytes()),
            (format!("{phase}-captured.log"), log.as_bytes()),
        ] {
            save(&name, bytes)?;
            members.push(member(&format!("{STATE}/{name}"), &name, 0o444)?);
        }
        executions.insert(phase.into(), json!({"unit":unit,"invocation_id":iid}));
    }
    let proof = json!({"schema":"horizon-two-producer-cycle-artifact-proof-v1","source_commit":commit.trim(),"production_sha256":IMAGE_SHA,"tests_passed":4,"strict_clippy_passed":true,"production_build_passed":true,"sources":sources,"executions":executions,"replay_launch_authorized":false,"resource_credit_bytes":0});
    save("artifact-proof.json", &serde_json::to_vec_pretty(&proof)?)?;
    members.push(member(
        &format!("{STATE}/artifact-proof.json"),
        "artifact-proof.json",
        0o444,
    )?);
    let plan = serde_json::to_vec_pretty(
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":members}),
    )?;
    save("plan.json", &plan)?;
    print!(
        "{}",
        command(
            SEALER,
            &[
                &format!("{STATE}/plan.json"),
                "--plan-sha256",
                &sha(&plan),
                "--self-sha256",
                SEALER_SHA
            ]
        )?
    );
    Ok(())
}
