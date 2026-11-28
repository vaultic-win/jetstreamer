//! Bind the completed epoch166 preparation for the separately sealed launcher.
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
struct Route {
    prepared: &'static str,
    root: &'static str,
    attempt: &'static str,
    schema: &'static str,
    stop: &'static str,
    stop_sha: &'static str,
}

const RETRY8: Route = Route {
    prepared: "/var/lib/jetstreamer/retry8-preparation-20261119-v1/epoch166/local3retry8/prepared.json",
    root: "/var/lib/jetstreamer/retry8-single166-guarded-launch-20261119-v1",
    attempt: "local3retry8",
    schema: "horizon-retry8-single166-launch-plan-v1",
    stop: "/var/lib/jetstreamer/retry7-preparation-20261118-v1/epoch166/local3retry7/guard-state-recovery-v2/receipts/stop-completion.json",
    stop_sha: "846c5f57fa2600a1aec5ee9ac0d3a32590b97d6982a66cc5db091f2fadda390e",
};
const INDEPENDENT: Route = Route {
    prepared: "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1/preparation/epoch166/local3retry9/prepared.json",
    root: "/var/lib/jetstreamer/horizon_runtime_data/epoch166-independent-cold-20261120-v1/launch-state",
    attempt: "local3retry9",
    schema: "horizon-independent-cold166-launch-plan-v1",
    stop: "/var/lib/jetstreamer/retry8-preparation-20261119-v1/epoch166/local3retry8/guard-state-recovery-v2/receipts/stop-completion.json",
    stop_sha: "b99e26a6836609dc68b4c646eb19ce2b2c0edd0d7547c80b1e0b517be4875b08",
};
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
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = std::env::args().skip(1).collect();
    let route = match args.as_slice() {
        [] => &RETRY8,
        [arg] if arg == "--independent" => &INDEPENDENT,
        _ => anyhow::bail!("usage: plan_launch166 [--independent]"),
    };
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
            "scripts/horizon_retry6_167_live166_stage_20261118_v1/src/bin/plan_launch166.rs"
        ])?
        .is_empty(),
        "tracked source changed"
    );
    let bytes = read_preparation(route)?;
    let plan = build_plan(route, &bytes, commit.trim())?;
    let output_root = format!("{}/epoch166", route.root);
    private(Path::new(route.root))?;
    private(Path::new(&output_root))?;
    ensure!(
        fs::read_dir(&output_root)?.next().is_none(),
        "launch state already used"
    );
    let path = format!("{}/launch-plan.json", route.root);
    let encoded = serde_json::to_vec_pretty(&plan)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    File::open(route.root)?.sync_all()?;
    println!(
        "{}",
        json!({"path":path,"sha256":sha(&encoded),"replay_launched":false})
    );
    Ok(())
}

fn read_preparation(route: &Route) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(route.prepared)?;
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
    let current = fs::symlink_metadata(route.prepared)?;
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
    Ok(bytes)
}

fn build_plan(route: &Route, bytes: &[u8], commit: &str) -> Result<Value> {
    let prepared: Value = serde_json::from_slice(bytes)?;
    ensure!(
        prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && prepared["epoch"] == 166
            && prepared["attempt"] == route.attempt
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
    let output_root = format!("{}/epoch166", route.root);
    if route.attempt == INDEPENDENT.attempt {
        ensure!(
            prepared["independent_worker_root"]
                == "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1"
                && prepared["independent_physical_cap_bytes"] == 309_237_645_312u64
                && prepared["replay_admission_receipt"] == false
                && prepared["guard_timer_started"] == false,
            "wrong independent preparation"
        );
        ensure!(
            sha(&fs::read(route.stop)?) == route.stop_sha,
            "prior stop changed"
        );
    }
    let plan = json!({"schema":route.schema,
        "owner":"/root","primary_thread":THREAD,"launch_authorized":true,
        "output_root":output_root,"prepared":{"path":route.prepared,"sha256":sha(bytes)},
        "data_fulfillment":contract,"source_commit":commit.trim(),"prior_stop_completion":{"path":route.stop,"sha256":route.stop_sha}});
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_plan_binds_exact_preparation_contract_and_prior_stop() {
        let contract = json!({"contract":{"path":"/fixture/contract","sha256":"c".repeat(64)},
            "deployment_seal":{"path":"/fixture/seal","sha256":"d".repeat(64)}});
        let mut prepared = json!({"schema":"horizon-standard-replacement-recipe-preparation-v1",
            "epoch":166,"attempt":"local3retry9","owner":"/root","primary_thread":THREAD,
            "replay_launched":false,"remote_mutations":false,"replay_admission_receipt":false,
            "guard_timer_started":false,"independent_physical_cap_bytes":309_237_645_312u64,
            "independent_worker_root":"/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1",
            "data_fulfillment":{"contract":contract}});
        let raw = serde_json::to_vec(&prepared).unwrap();
        let plan = build_plan(&INDEPENDENT, &raw, "fixture").unwrap();
        assert_eq!(plan["prepared"]["sha256"], sha(&raw));
        assert_eq!(plan["data_fulfillment"], contract);
        assert_eq!(
            plan["prior_stop_completion"]["sha256"],
            INDEPENDENT.stop_sha
        );
        assert_eq!(plan["schema"], INDEPENDENT.schema);
        assert!(build_plan(&RETRY8, &raw, "fixture").is_err());
        prepared["guard_timer_started"] = json!(true);
        assert!(
            build_plan(
                &INDEPENDENT,
                &serde_json::to_vec(&prepared).unwrap(),
                "fixture"
            )
            .is_err()
        );
    }
    #[test]
    fn original_route_reproduces_previously_used_launch_plan() {
        let old: Value = serde_json::from_slice(
            &fs::read(Path::new(RETRY8.root).join("launch-plan.json")).unwrap(),
        )
        .unwrap();
        let actual = build_plan(
            &RETRY8,
            &read_preparation(&RETRY8).unwrap(),
            old["source_commit"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(actual, old);
    }
}
