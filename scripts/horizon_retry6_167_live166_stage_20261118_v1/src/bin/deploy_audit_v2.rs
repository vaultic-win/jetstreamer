//! Prepare a separately sealed audit controller successor; never switch/start it.
//! The original state, inventory, credentials, reader generations, and logs remain.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const ROOT: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v2";
const STATE: &str = "/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v2";
const PREDECESSOR: &str =
    "/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v1";
const PREDECESSOR_RECEIPT_SHA: &str =
    "e0549934b66bc3418a637ca1da8f427af60693e87932fcff88aaf6706795daf5";
const CREDENTIALS: &str =
    "/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1/credentials.env";
const READERS: &str = "/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1";
const UNIT: &str = "horizon-r2-chronological-plugin-audit-20261118-v1.service";
const REPO: &str = "/home/sol/workspace/jetstreamer";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const RUNNER_SOURCE: &str = "scripts/horizon_r2_chronological_plugin_audit_20261118_v1";
const HELPER_SOURCE: &str = "scripts/horizon_retry6_167_live166_stage_20261118_v1";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(m.is_file(), "expected a regular file: {}", path.display());
    Ok(file)
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = regular(path)?;
    ensure!(file.metadata()?.len() <= max, "file exceeds bound");
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "file grew beyond bound");
    Ok(bytes)
}
fn hash(path: &Path) -> Result<String> {
    let mut f = regular(path)?;
    let mut digest = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn run(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn git(args: &[&str]) -> Result<String> {
    run(Command::new("/usr/bin/git").arg("-C").arg(REPO).args(args))
}
fn save(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    File::open(path.parent().context("missing parent")?)?.sync_all()?;
    Ok(())
}
fn member(path: &Path, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":hash(path)?,"mode":mode}))
}
fn root_directory(path: &Path, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == mode && path.canonicalize()? == path,
        "unexpected existing directory identity: {}",
        path.display()
    );
    Ok(())
}
fn predecessor_member(receipt: &Value, name: &str) -> Result<Vec<u8>> {
    let members = receipt["members"]
        .as_array()
        .context("predecessor members missing")?;
    let rows: Vec<_> = members.iter().filter(|m| m["name"] == name).collect();
    ensure!(rows.len() == 1, "predecessor member absent/duplicated");
    let path = Path::new(PREDECESSOR).join(name);
    let file = regular(&path)?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o7777 == 0o444 && m.nlink() == 1,
        "predecessor metadata not root-sealed"
    );
    let bytes = read(&path, 16 * 1024 * 1024)?;
    ensure!(
        rows[0]["sha256"] == sha(&bytes) && rows[0]["bytes"].as_u64() == Some(bytes.len() as u64),
        "predecessor member changed"
    );
    Ok(bytes)
}
fn successor_unit(predecessor: &str) -> Result<String> {
    let old = format!("ExecStart={PREDECESSOR}/audit run {PREDECESSOR}/config.json");
    let new = format!("ExecStart={DEST}/audit run {DEST}/config.json");
    ensure!(
        predecessor
            .lines()
            .filter(|line| line.starts_with("ExecStart="))
            .count()
            == 1
            && predecessor.lines().filter(|line| *line == old).count() == 1,
        "predecessor ExecStart mismatch"
    );
    let result = predecessor.replacen(&old, &new, 1);
    // Byte-for-byte identity everywhere except the single ExecStart line is the
    // resource/config/credential continuity guarantee. No unit is installed here.
    ensure!(
        result.replacen(&new, &old, 1) == predecessor,
        "unexpected successor unit changes"
    );
    Ok(result)
}
fn validate_config(config: &Value) -> Result<()> {
    ensure!(
        config["state_directory"] == STATE
            && config["reserve_bytes"] == 32u64 << 30
            && config["max_archive_bytes"] == 16u64 << 30
            && config["build_reserve_bytes"] == 16u64 << 30
            && config["threads"] == 4
            && config["build_jobs"] == 2,
        "existing audit allocation changed"
    );
    Ok(())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root required");
    let args: Vec<_> = env::args().collect();
    ensure!(args.len() == 3, "deploy_audit_v2 RUNNER EXPECTED_SHA256");
    let runner = PathBuf::from(&args[1]);
    ensure!(
        runner.is_absolute() && runner.canonicalize()? == runner,
        "runner path must be canonical"
    );
    ensure!(hash(&runner)? == args[2], "runner image changed");
    let commit = git(&["rev-parse", "HEAD"])?.trim().to_owned();
    let origin = git(&["rev-parse", "origin/account-updates"])?
        .trim()
        .to_owned();
    git(&[
        "merge-base",
        "--is-ancestor",
        &commit,
        "origin/account-updates",
    ])?;
    ensure!(
        git(&[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            RUNNER_SOURCE,
            HELPER_SOURCE
        ])?
        .is_empty(),
        "audit/helper source changed or uncommitted"
    );
    let mut sources = Vec::new();
    for relative in [RUNNER_SOURCE, HELPER_SOURCE] {
        let files = git(&["ls-files", "--", relative])?;
        ensure!(!files.trim().is_empty(), "source not committed");
        for name in files.lines() {
            let path = Path::new(REPO).join(name);
            let bytes = fs::read(&path)?;
            let out = Command::new("/usr/bin/git")
                .arg("-C")
                .arg(REPO)
                .args(["show", &format!("{commit}:{name}")])
                .output()?;
            ensure!(
                out.status.success() && out.stdout == bytes,
                "source differs from committed bytes: {name}"
            );
            sources.push(json!({"path":name,"sha256":sha(&bytes)}));
        }
    }
    root_directory(Path::new(STATE), 0o700)?;
    root_directory(Path::new(READERS), 0o755)?;
    root_directory(Path::new(PREDECESSOR), 0o555)?;
    let credentials = fs::symlink_metadata(CREDENTIALS)?;
    ensure!(
        credentials.is_file()
            && credentials.uid() == 0
            && credentials.mode() & 0o7777 == 0o600
            && credentials.nlink() == 1,
        "existing credential custody changed"
    );
    // Do not read, copy, log, or recreate credentials. Preserve their exact path.
    let receipt_bytes = read(
        &Path::new(PREDECESSOR).join("deployment-seal-receipt.json"),
        1024 * 1024,
    )?;
    ensure!(
        sha(&receipt_bytes) == PREDECESSOR_RECEIPT_SHA,
        "unexpected predecessor seal"
    );
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    ensure!(
        receipt["destination"] == PREDECESSOR && receipt["sealer_sha256"] == SEALER_SHA,
        "predecessor seal identity mismatch"
    );
    let config_bytes = predecessor_member(&receipt, "config.json")?;
    let config: Value = serde_json::from_slice(&config_bytes)?;
    validate_config(&config)?;
    let accepted: Value = serde_json::from_slice(&read(
        &Path::new(STATE).join("accepted-config.json"),
        1024 * 1024,
    )?)?;
    ensure!(
        accepted == config,
        "state configuration differs from sealed v1 configuration"
    );
    let inventory_sha = hash(&Path::new(STATE).join("inventory.json"))?;
    let predecessor_unit = String::from_utf8(predecessor_member(&receipt, UNIT)?)?;
    ensure!(
        predecessor_unit
            .lines()
            .any(|l| l == format!("EnvironmentFile={CREDENTIALS}")),
        "credential path changed"
    );
    let unit = successor_unit(&predecessor_unit)?;
    ensure!(
        hash(Path::new(SEALER))? == SEALER_SHA,
        "approved sealer changed"
    );
    ensure!(
        !Path::new(ROOT).try_exists()? && !Path::new(DEST).try_exists()?,
        "v2 deployment already exists; preserve it"
    );
    fs::create_dir(ROOT)?;
    fs::set_permissions(ROOT, fs::Permissions::from_mode(0o700))?;
    File::open(Path::new(ROOT).parent().unwrap())?.sync_all()?;
    let config_path = Path::new(ROOT).join("config.json");
    save(&config_path, &config_bytes, 0o444)?;
    let unit_path = Path::new(ROOT).join(UNIT);
    save(&unit_path, unit.as_bytes(), 0o444)?;
    let proof = json!({"schema":"horizon-r2-chronological-audit-deployment-v2","source_commit":commit,
        "origin_account_updates_commit":origin,"source_commit_contained_in_origin":true,"runner_sha256":args[2],"source_files":sources,
        "predecessor_deployment":PREDECESSOR,"predecessor_seal_sha256":PREDECESSOR_RECEIPT_SHA,
        "state_directory":STATE,"inventory_sha256":inventory_sha,"credentials_path_preserved":CREDENTIALS,"reader_root_preserved":READERS,
        "config_preserved_byte_for_byte":true,"unit_change":"only ExecStart image/config deployment paths",
        "root_reserve_bytes":32u64<<30,"max_archive_bytes":16u64<<30,"build_reserve_bytes":16u64<<30,
        "failed_attempt_evidence_preserved":true,"service_switch_authorized":false,"replay_launch_authorized":false,"r2_mutations_authorized":false});
    let proof_path = Path::new(ROOT).join("artifact-proof.json");
    save(&proof_path, &serde_json::to_vec_pretty(&proof)?, 0o444)?;
    let plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[
        member(&runner,"audit",0o555)?,member(&config_path,"config.json",0o444)?,member(&unit_path,UNIT,0o444)?,member(&proof_path,"artifact-proof.json",0o444)?]});
    let plan_bytes = serde_json::to_vec_pretty(&plan)?;
    let plan_path = Path::new(ROOT).join("seal-plan.json");
    save(&plan_path, &plan_bytes, 0o400)?;
    run(Command::new(SEALER).arg(&plan_path).args([
        "--plan-sha256",
        &sha(&plan_bytes),
        "--self-sha256",
        SEALER_SHA,
    ]))?;
    ensure!(
        hash(&Path::new(STATE).join("inventory.json"))? == inventory_sha,
        "frozen inventory changed during deployment"
    );
    println!(
        "sealed={DEST}; preserved_state={STATE}; existing service unchanged; no launch performed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successor_preserves_resources_state_credentials_and_unit_identity() {
        let old = format!(
            "[Service]\nUser=root\nEnvironmentFile={CREDENTIALS}\nWorkingDirectory={STATE}\nExecStart={PREDECESSOR}/audit run {PREDECESSOR}/config.json\nMemoryMax=32G\nCPUQuota=400%\nReadWritePaths={STATE} /home/sol/.cargo {READERS}\n"
        );
        let new = successor_unit(&old).unwrap();
        let before: Vec<_> = old
            .lines()
            .filter(|l| !l.starts_with("ExecStart="))
            .collect();
        let after: Vec<_> = new
            .lines()
            .filter(|l| !l.starts_with("ExecStart="))
            .collect();
        assert_eq!(before, after);
        assert!(new.contains(&format!("ExecStart={DEST}/audit run {DEST}/config.json")));
    }
    #[test]
    fn unknown_or_duplicate_predecessor_exec_is_rejected() {
        assert!(successor_unit("ExecStart=/other/audit run /other/config\n").is_err());
        let line = format!("ExecStart={PREDECESSOR}/audit run {PREDECESSOR}/config.json\n");
        assert!(successor_unit(&(line.clone() + &line)).is_err());
    }
    #[test]
    fn allocation_change_is_not_silently_accepted() {
        let mut cfg = json!({"state_directory":STATE,"reserve_bytes":32u64<<30,"max_archive_bytes":16u64<<30,"build_reserve_bytes":16u64<<30,"threads":4,"build_jobs":2});
        validate_config(&cfg).unwrap();
        cfg["reserve_bytes"] = json!(0);
        assert!(validate_config(&cfg).is_err());
    }
}
