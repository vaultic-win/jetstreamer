//! Seal the qualified exact-141 retirement image and bind its custody plans.
//! This helper never retires data or mutates R2.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};

const REPO: &str = "/home/sol/workspace/jetstreamer";
const ROOT: &str = "/var/lib/jetstreamer/holding141-retirement-deployment-20261118-v1";
const DEST: &str = "/usr/local/lib/jetstreamer/horizon-holding141-retirement-20261118-v1";
const IMAGE: &str = "/tmp/holding141-target/debug/jetstreamer-r2";
const IMAGE_SHA: &str = "885e12ccea8a66892693d6542e1f2781b707b14b63ff50488128d7b420bccf8c";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const ELIGIBILITY: &str = "/usr/local/lib/jetstreamer/horizon-closed141-input-holding-plan-20261118-v1/eligibility.json";

fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn run(c: &mut Command) -> Result<String> {
    let o = c.output()?;
    ensure!(o.status.success(), "{c:?}: {}", String::from_utf8_lossy(&o.stderr));
    Ok(String::from_utf8(o.stdout)?)
}
fn git(a: &[&str]) -> Result<String> { run(Command::new("git").arg("-C").arg(REPO).args(a)) }
fn bind(p: &str) -> Result<Value> { Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)})) }
fn save(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(!name.contains('/'), "leaf required");
    let p = format!("{ROOT}/{name}");
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o400)
        .custom_flags(libc::O_NOFOLLOW).open(&p)?;
    f.write_all(bytes)?; f.sync_all()?; File::open(ROOT)?.sync_all()?;
    bind(&p)
}
fn json_file(name: &str, v: &Value) -> Result<Value> { save(name, &serde_json::to_vec_pretty(v)?) }
fn member(path: &str, name: &str, mode: u32) -> Result<Value> {
    Ok(json!({"source":path,"name":name,"sha256":sha(&fs::read(path)?),"mode":mode}))
}
fn native(unit: &str, iid: Option<&str>, leaf: &str) -> Result<Value> {
    let out = run(Command::new("/usr/bin/systemctl").args(["show",unit,"--all"]))?;
    for expected in ["ActiveState=active", "SubState=exited", "MainPID=0", "ControlPID=0", "Result=success", "ExecMainStatus=0"] {
        ensure!(out.lines().any(|s|s==expected), "native success missing: {unit} {expected}");
    }
    if let Some(iid) = iid { ensure!(out.lines().any(|s|s==format!("InvocationID={iid}")), "build invocation changed"); }
    save(leaf,out.as_bytes())
}
fn main() -> Result<()> {
    ensure!(unsafe{libc::geteuid()}==0,"Root required");
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() >= 2,"deploy_retire141 seal | check-plan CUSTODY | retire-plan CUSTODY CHECK");
    let commit = git(&["rev-parse","HEAD"])?.trim().to_owned();
    git(&["merge-base","--is-ancestor",&commit,"origin/account-updates"])?;
    ensure!(git(&["status","--porcelain","--untracked-files=no","--","jetstreamer-r2","jetstreamer-horizon-observe","Cargo.toml","Cargo.lock","scripts/horizon_retry6_167_live166_stage_20261118_v1"])?.is_empty(),"relevant source changed");
    if a[1]=="seal" {
        ensure!(a.len()==2,"seal takes no argument");
        // Changes after this build are operational source only. Require exact
        // equivalence for the built package and its observation dependency.
        git(&["diff","--exit-code","72751e30","HEAD","--","jetstreamer-r2","jetstreamer-horizon-observe","Cargo.toml","Cargo.lock"])?;
        ensure!(sha(&fs::read(IMAGE)?)==IMAGE_SHA,"qualified image changed");
        ensure!(sha(&fs::read(SEALER)?)==SEALER_SHA,"sealer changed");
        fs::create_dir(ROOT)?; fs::set_permissions(ROOT,fs::Permissions::from_mode(0o700))?;
        let build = native("horizon-holding141-retirement-build-20261118-v2.service",Some("6c11754a602e40c89ef375c1f49a3374"),"build-native.txt")?;
        let tests = native("horizon-holding141-retirement-tests-20261118-v1.service",None,"tests-native.txt")?;
        let log = run(Command::new("/usr/bin/journalctl").args(["-u","horizon-holding141-retirement-tests-20261118-v1.service","--no-pager","--all","-o","cat"]))?;
        ensure!(log.contains("holding::epoch141_retire::tests::retirement_markers_require_durable_predecessors ... ok") && log.contains("test result: ok. 1 passed; 0 failed;"),"targeted retirement test missing");
        let log = save("tests.log",log.as_bytes())?;
        let proof=json_file("artifact-proof.json",&json!({"schema":"horizon-exact141-retirement-artifact-v1","source_commit":commit,
            "equivalent_build_source_commit":"72751e30","source_contained_in_fetched_origin":true,
            "image_sha256":IMAGE_SHA,"build":build,"tests":tests,"test_log":log,
            "scope":"holding-check-retire141 and holding-retire141 only; exact original compressed input after custody",
            "replay_launch_authorized":false,"canonical_publication_authorized":false,"remote_mutations_authorized":false}))?;
        let plan=json_file("seal-plan.json",&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,
            "members":[member(IMAGE,"jetstreamer-r2",0o555)?,member(proof["path"].as_str().unwrap(),"artifact-proof.json",0o444)?]}))?;
        run(Command::new(SEALER).args([plan["path"].as_str().unwrap(),"--plan-sha256",plan["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
        println!("sealed={DEST}; no retirement performed");
    } else {
        let retire=a[1]=="retire-plan";
        ensure!((retire && a.len()==4) || (a[1]=="check-plan" && a.len()==3),"invalid plan arguments");
        ensure!(Path::new(&a[2]).is_absolute(),"absolute custody path required");
        let custody:Value=serde_json::from_slice(&fs::read(&a[2])?)?;
        ensure!(custody["source"]=="/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2"
            && custody["sha256"]=="7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b", "foreign custody");
        let check=if retire { Some(bind(a.get(3).context("prior check")?)?) } else { None };
        println!("{}",json_file(if retire {"retire-plan.json"} else {"check-plan.json"},&json!({
            "schema":"jetstreamer-horizon-holding-retire141-plan-v1","mapping":bind(MAPPING)?,
            "eligibility":bind(ELIGIBILITY)?,"custody":bind(&a[2])?,"prior_check":check}))?);
    }
    Ok(())
}
