//! Seal the qualified167 successor; this performs no replay admission or launch.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const REPO: &str = "/home/sol/workspace/jetstreamer";
const PACKAGE: &str = "scripts/horizon_retry7_167_20261119_v1/guard";
const OWN_SOURCE: &str =
    "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/deploy_guard167retry7.rs";
const ROOT: &str = "/var/lib/jetstreamer/epoch167-retry7-live166retry8-guard-20261119-v1";
const DEST: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-guard-20261119-v1";
const IMAGE: &str = "/home/sol/workspace/jetstreamer/scripts/horizon_retry8_166_20261119_v1/guard/target/release/guard";
const IMAGE_SHA: &str = "e2821006426c497f25ecfdc8da26b63136d174a92c0ac15f78068bbc1078e581";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn run(c: &mut Command) -> Result<Vec<u8>> {
    let o = c.output()?;
    ensure!(
        o.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(o.stdout)
}
fn git(args: &[&str]) -> Result<Vec<u8>> {
    run(Command::new("git")
        .args(["-c", &format!("safe.directory={REPO}"), "-C", REPO])
        .args(args))
}
fn bind(path: &str) -> Result<Value> {
    Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)}))
}
fn save(name: &str, bytes: &[u8]) -> Result<Value> {
    let path = format!("{ROOT}/{name}");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    bind(&path)
}
fn field<'a>(s: &'a str, k: &str) -> Result<&'a str> {
    s.lines()
        .find_map(|l| l.strip_prefix(&format!("{k}=")))
        .with_context(|| format!("missing {k}"))
}
fn accepted_native(s: &str) -> Result<()> {
    for (k, v) in [
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
        ensure!(field(s, k)? == v, "qualification differs: {k}");
    }
    let iid = field(s, "InvocationID")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "missing genuine IID"
    );
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?)?;
    let commit = commit.trim();
    git(&[
        "merge-base",
        "--is-ancestor",
        commit,
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
        "required source not published/clean"
    );
    let paths = String::from_utf8(git(&["ls-files", "--", PACKAGE, OWN_SOURCE])?)?;
    let mut sources = serde_json::Map::new();
    for p in paths.lines() {
        let b = fs::read(Path::new(REPO).join(p))?;
        ensure!(
            git(&["show", &format!("HEAD:{p}")])? == b,
            "uncommitted source {p}"
        );
        sources.insert(p.into(), json!(sha(&b)));
    }
    ensure!(
        sources.len() == 15 && sha(&fs::read(IMAGE)?) == IMAGE_SHA,
        "source closure or image mismatch"
    );
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA, "sealer changed");
    fs::DirBuilder::new().mode(0o700).create(ROOT)?;
    let mut executions = serde_json::Map::new();
    for phase in ["build", "test-build", "test-root"] {
        let unit = format!("horizon-retry7-167-guard-{phase}-20261119-v1.service");
        let native=run(Command::new("systemctl").args(["show",&unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec"]))?;
        let s = std::str::from_utf8(&native)?;
        accepted_native(s)?;
        let exec = field(s, "ExecStart")?;
        ensure!(
            !exec.contains("--features") && !exec.contains("--all-features"),
            "foreign features"
        );
        if phase == "test-root" {
            ensure!(
                exec.contains("/guard/target/release/deps/guard-d2f95529e7f2911b"),
                "foreign test image"
            );
        } else {
            ensure!(
                exec.contains(&format!("{PACKAGE}/Cargo.toml")) && exec.contains("--release"),
                "foreign manifest/profile"
            );
        }
        let log = run(Command::new("journalctl").args([
            "--no-pager",
            "-o",
            "cat",
            &format!("_SYSTEMD_INVOCATION_ID={}", field(s, "InvocationID")?),
        ]))?;
        if phase == "test-root" {
            let l = std::str::from_utf8(&log)?;
            for expected in [
                "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                "test data_fulfillment::tests::fresh167_retry7_retains_live166retry8_and_512gib_cap ... ok",
                "test data_fulfillment::tests::revised_cleanup_witness_retains_only_qualified_survivors ... ok",
            ] {
                ensure!(l.contains(expected), "missing qualified test evidence");
            }
        }
        executions.insert(phase.into(),json!({"unit":unit,"native":save(&format!("{phase}.native"),&native)?,"journal":save(&format!("{phase}.log"),&log)?}));
    }
    let proof = save(
        "artifact-proof.json",
        &serde_json::to_vec_pretty(&json!({
            "schema":"horizon-revised-original-slot-witness-guard-artifact-proof-v1","epoch":167,"attempt":"local3retry7","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
            "source_commit":commit,"source_commit_verified_on_origin_account_updates":true,"source_files":sources,"source_and_production_hash_match":true,
            "production":{"path":format!("{DEST}/guard"),"sha256":IMAGE_SHA,"feature_flags":[]},
            "tests":{"passed":99,"failed":0,"ignored":0,"includes_current_twelve_file_witness":true,"includes_live166_retry8_additive_floor_scope":true},
            "executions":executions,"whole_lane_cap_bytes":549755813888u64,"raw_floor_bytes":6829053656882u64,"replay_launch_authorized":false,"remote_mutations":false
        }))?,
    )?;
    let plan = save(
        "seal-plan.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[
                {"source":IMAGE,"name":"guard","sha256":IMAGE_SHA,"mode":365},
                {"source":proof["path"],"name":"artifact-proof.json","sha256":proof["sha256"],"mode":292}
            ]}),
        )?,
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
        json!({"source_commit":commit,"guard":bind(&format!("{DEST}/guard"))?,"proof":bind(&format!("{DEST}/artifact-proof.json"))?,"seal":bind(&format!("{DEST}/deployment-seal-receipt.json"))?})
    );
    Ok(())
}
