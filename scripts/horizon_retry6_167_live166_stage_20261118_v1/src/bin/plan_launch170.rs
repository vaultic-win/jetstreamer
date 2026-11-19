//! Bind the completed epoch170 preparation for the separately sealed launcher.
//! This metadata command neither admits nor starts a producer.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};

const REPO: &str = "/home/sol/workspace/jetstreamer";
const PREPARED: &str =
    "/var/lib/jetstreamer/retry6-170-preparation-20261118-v1/epoch170/local3retry6/prepared.json";
const ROOT: &str = "/var/lib/jetstreamer/retry6-single170-guarded-launch-20261119-v1";
const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn git(args: &[&str]) -> Result<String> {
    let result = Command::new("git")
        .arg("-C")
        .arg(REPO)
        .args(args)
        .output()?;
    ensure!(
        result.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
fn private(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(path.parent().context("directory parent")?)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700 && path.canonicalize()? == path,
        "unsafe metadata directory"
    );
    Ok(())
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "Root required; plan_launch170 takes no arguments"
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
            "--untracked-files=no",
            "--",
            "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/plan_launch170.rs"
        ])?
        .is_empty(),
        "tracked source changed"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(PREPARED)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 32 << 20,
        "unsafe preparation"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((32 << 20) + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let current = fs::symlink_metadata(PREPARED)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && after.dev() == current.dev()
            && after.ino() == current.ino(),
        "preparation changed"
    );
    let prepared: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && prepared["epoch"] == 170
            && prepared["attempt"] == "local3retry6"
            && prepared["owner"] == "/root"
            && prepared["primary_thread"] == THREAD
            && prepared["replay_launched"] == false
            && prepared["remote_mutations"] == false,
        "foreign or already consumed preparation"
    );
    let contract = &prepared["data_fulfillment"]["contract"];
    ensure!(
        contract["contract"]["path"].is_string()
            && contract["contract"]["sha256"].is_string()
            && contract["deployment_seal"]["path"].is_string()
            && contract["deployment_seal"]["sha256"].is_string(),
        "missing bound DATA contract"
    );
    let output_root = format!("{ROOT}/epoch170");
    private(Path::new(ROOT))?;
    private(Path::new(&output_root))?;
    ensure!(
        fs::read_dir(&output_root)?.next().is_none(),
        "launch state already used"
    );
    let plan = json!({"schema":"horizon-retry6-single170-launch-plan-v1",
        "owner":"/root","primary_thread":THREAD,"launch_authorized":true,
        "output_root":output_root,"prepared":{"path":PREPARED,"sha256":sha(&bytes)},
        "data_fulfillment":contract,"source_commit":commit.trim()});
    let path = format!("{ROOT}/launch-plan.json");
    let encoded = serde_json::to_vec_pretty(&plan)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    File::open(ROOT)?.sync_all()?;
    println!(
        "{}",
        json!({"path":path,"sha256":sha(&encoded),"replay_launched":false})
    );
    Ok(())
}
