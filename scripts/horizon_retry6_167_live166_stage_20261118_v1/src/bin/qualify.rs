//! Local qualification metadata and normal deployment sealing; no replay or R2 authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, process::Command};

const STATE: &str = "/var/lib/jetstreamer/epoch167-retry6-live166retry7-prepare-20261118-v3";
const SOURCE: &str = "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-prepare-source-20261118-v3";
const RUNTIME: &str = "/usr/local/lib/jetstreamer/horizon-epoch167-retry6-live166retry7-prepare-20261118-v3";
const TARGET: &str = "/var/lib/jetstreamer/epoch167-retry6-zeropeer-20261118-v2/cargo-target/release/prepare";
const REPO: &str = "/home/sol/workspace/jetstreamer";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn bind(path: &str) -> Result<Value> { Ok(json!({"path":path,"sha256":sha(&fs::read(path)?)})) }
fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output()?;
    ensure!(out.status.success(), "command failed: {:?}: {}",cmd,String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?)
}
fn write(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/'), "leaf only");
    let path = format!("{STATE}/{name}");
    let mut f = OpenOptions::new().create_new(true).write(true).custom_flags(libc::O_NOFOLLOW).mode(0o400).open(&path)?;
    f.write_all(bytes)?; f.sync_all()?; File::open(STATE)?.sync_all()?; bind(&path)
}
fn json_file(name: &str, value: &Value) -> Result<Value> { write(name,&serde_json::to_vec_pretty(value)?) }
fn member(path: &str, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":sha(&fs::read(path)?),"mode":mode}))
}
fn seal(name: &str, destination: &str, members: Value) -> Result<Value> {
    let plan=json_file(name,&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}))?;
    ensure!(sha(&fs::read(SEALER)?) == SEALER_SHA,"sealer changed");
    output(Command::new(SEALER).arg(plan["path"].as_str().unwrap()).args(["--plan-sha256",plan["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
    bind(&format!("{destination}/deployment-seal-receipt.json"))
}
fn native(unit: &str, leaf: &str) -> Result<Value> {
    let raw=output(Command::new("/usr/bin/systemctl").args(["show",unit,"--all"]))?;
    for required in ["Result=success","ExecMainStatus=0","ActiveState=active","SubState=exited"] {
        ensure!(raw.lines().any(|s|s==required),"unit {unit} missing terminal success: {required}");
    }
    write(leaf,raw.as_bytes())
}
fn git(args: &[&str]) -> Result<String> { output(Command::new("git").arg("-C").arg(REPO).args(args)) }
fn run() -> Result<()> {
    ensure!(unsafe {libc::geteuid()} == 0,"Root required");
    let args:Vec<_>=std::env::args().collect();
    ensure!(args.len()==2,"qualify source|runtime|stage");
    let commit=git(&["rev-parse","HEAD"])? .trim().to_owned();
    git(&["merge-base","--is-ancestor",&commit,"origin/account-updates"])?;
    ensure!(git(&["status","--porcelain","--untracked-files=no"])?.is_empty(),"tracked tree changed");
    if args[1]=="source" {
        fs::create_dir(STATE)?; fs::set_permissions(STATE,fs::Permissions::from_mode(0o700))?;
        let old:Value=serde_json::from_slice(&fs::read("/var/lib/jetstreamer/epoch167-retry6-live166retry7-prepare-20261118-v2/source-seal-plan.json")?)?;
        let mut members=Vec::new();
        for m in old["members"].as_array().context("source members")? {
            members.push(member(m["source"].as_str().context("source path")?,m["name"].as_str().context("source name")?,292)?);
        }
        println!("{}",seal("source-seal-plan.json",SOURCE,json!(members))?);
    } else if args[1]=="runtime" {
        let build=native("horizon-167-live166retry7-prepare-build-20261118-v3.service","build-native.txt")?;
        let tests=native("horizon-167-live166retry7-prepare-tests-20261118-v3.service","tests-native.txt")?;
        let log=output(Command::new("/usr/bin/journalctl").args(["-u","horizon-167-live166retry7-prepare-tests-20261118-v3.service","--no-pager","--all","-o","cat"]))?;
        ensure!(log.contains("test result: ok. 298 passed; 0 failed;"),"full test result missing");
        let test_log=write("tests.log",log.as_bytes())?;
        let proof=json!({"schema":"horizon-live166retry7-preparer-build-proof-v1","owner":"/root",
            "primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","epoch":167,"attempt":"local3retry6",
            "source_commit":commit,"source_commit_verified_on_origin_account_updates":true,
            "source_seal":bind(&format!("{SOURCE}/deployment-seal-receipt.json"))?,"production":bind(TARGET)?,
            "native":{"build":build,"tests":tests},"tests_passed":298,"tests_failed":0,"test_output":test_log,
            "features":["preparation"],"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false});
        let p=json_file("artifact-proof.json",&proof)?;
        println!("{}",seal("runtime-seal-plan.json",RUNTIME,json!([member(TARGET,"prepare",365)?,member(p["path"].as_str().unwrap(),"artifact-proof.json",292)?]))?);
    } else if args[1]=="stage" {
        let binary=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/target/release/horizon-retry6-167-live166-stage");
        let source=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/src/main.rs");
        let manifest=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml");
        let lock=format!("{REPO}/scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.lock");
        let p=json_file("stage-artifact-proof.json",&json!({"source_commit":commit,
            "source_commit_verified_on_origin_account_updates":true,"production":bind(&binary)?,
            "source":bind(&source)?,"manifest":bind(&manifest)?,"lock":bind(&lock)?,
            "replay_launch_authorized":false}))?;
        println!("{}",seal("stage-runtime-seal-plan.json","/usr/local/lib/jetstreamer/horizon-epoch167-live166-stage-20261118-v3",
            json!([member(&binary,"stage",365)?,member(&source,"main.rs",292)?,member(&manifest,"Cargo.toml",292)?,member(&lock,"Cargo.lock",292)?,member(p["path"].as_str().unwrap(),"artifact-proof.json",292)?]))?);
    } else { anyhow::bail!("unknown operation"); }
    Ok(())
}
fn main() { if let Err(e)=run(){ eprintln!("{e:#}"); std::process::exit(1); } }
