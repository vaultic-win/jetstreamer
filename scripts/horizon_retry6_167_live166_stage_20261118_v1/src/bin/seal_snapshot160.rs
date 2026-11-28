//! Seal exact snapshot160 cleanup after native qualification. No snapshot unlink.
use anyhow::{Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::{self,File,OpenOptions},io::Write,os::unix::fs::{DirBuilderExt,OpenOptionsExt},process::Command};
const REPO:&str="/home/sol/workspace/jetstreamer";
const ROOT:&str="/var/lib/jetstreamer/snapshot160-private-retire-deploy-20261119-v1";
const DEST:&str="/usr/local/lib/jetstreamer/horizon-snapshot160-cleanup-20261119-v1";
const PACKAGE:&str="scripts/horizon_snapshot160_cleanup_20261119_v1";
const IMAGE:&str="/tmp/snapshot152-retire-target/release/horizon-snapshot160-cleanup";
const IMAGE_SHA:&str="329dad1d60fa8e8bdc0d5d7cb86d46ad1fcb0c1594aab7d0fcb8648cf63c01d1";
const SEALER:&str="/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA:&str="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn run(c:&mut Command)->Result<Vec<u8>>{let o=c.output()?;ensure!(o.status.success(),"{c:?}: {}",String::from_utf8_lossy(&o.stderr));Ok(o.stdout)}
fn save(leaf:&str,b:&[u8])->Result<String>{let p=format!("{ROOT}/{leaf}");let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(&p)?;f.write_all(b)?;f.sync_all()?;File::open(ROOT)?.sync_all()?;Ok(p)}
fn main()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 let git=|a:&[&str]|run(Command::new("git").arg("-C").arg(REPO).args(a));
 let commit=String::from_utf8(git(&["rev-parse","HEAD"])?)?;
 git(&["merge-base","--is-ancestor",commit.trim(),"origin/account-updates"])?;
 ensure!(git(&["status","--porcelain","--untracked-files=no","--",PACKAGE,"jetstreamer-horizon-observe"])?.is_empty(),"relevant source changed");
 ensure!(sha(&fs::read(IMAGE)?)==IMAGE_SHA && sha(&fs::read(SEALER)?)==SEALER_SHA,"qualified image or sealer changed");
 fs::DirBuilder::new().mode(0o700).create(ROOT)?;
 let mut executions=Vec::new();
 for (phase,suffix,iid,summary) in [
 ("test-build","v2","2f2b172aeb3346588912f7827680e628","test result: ok. 5 passed; 0 failed; 1 ignored;"),
 ("native-check","v2","f247c6ec400e47708388e9467bd0cff8","test result: ok. 1 passed; 0 failed; 0 ignored;"),
 ("production-build","v1","a3dc9ea0faa7490fa0d58f50ee75e6b8",""),
 ("clippy","v1","ade0858302fa407781d5f94fb99f72e4","") ] {
 let unit=format!("horizon-snapshot160-retirement-{phase}-20261119-{suffix}.service");
 let native=run(Command::new("/usr/bin/systemctl").args(["show",&unit,"-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,ExecStart,Environment,MemoryMax,CPUQuotaPerSecUSec,TasksMax"]))?;
 let text=std::str::from_utf8(&native)?;
 for line in ["ActiveState=active","SubState=exited","MainPID=0","ControlPID=0","Result=success","ExecMainStatus=0","CPUQuotaPerSecUSec=1s"] {ensure!(text.lines().any(|l|l==line),"{unit}: {line} missing");}
 ensure!(text.lines().any(|l|l==format!("InvocationID={iid}")),"native invocation differs");
 let log=run(Command::new("/usr/bin/journalctl").args(["--no-pager","--all","-o","cat",&format!("_SYSTEMD_INVOCATION_ID={iid}")]))?;
 ensure!(summary.is_empty() || std::str::from_utf8(&log)?.contains(summary),"test summary differs");
 let n=save(&format!("{phase}-native.txt"),&native)?;let l=save(&format!("{phase}.log"),&log)?;
 executions.push(json!({"unit":unit,"invocation_id":iid,"native":{"path":n,"sha256":sha(&native)},"log":{"path":l,"sha256":sha(&log)}}));
 }
 let mut sources=serde_json::Map::new();
 for path in String::from_utf8(git(&["ls-files","--",PACKAGE,"jetstreamer-horizon-observe"])?)?.lines() {
 let bytes=fs::read(format!("{REPO}/{path}"))?;ensure!(git(&["show",&format!("HEAD:{path}")])?==bytes,"unpublished source");sources.insert(path.into(),json!(sha(&bytes)));
 }
 ensure!(sources.len()>3,"incomplete source closure");
 let proof=json!({"schema":"horizon-snapshot160-private-retire-build-proof-v1","source_commit":commit.trim(),"source_verified_on_fetched_origin":true,"source_paths":sources,"production_sha256":IMAGE_SHA,"retirement_scope":[0],"retained_immutable_source_preserved":true,"tests_passed":5,"native_full_hash_and_reference_test_passed":true,"strict_all_targets_clippy_passed":true,"executions":executions,"remote_mutations":false});
 let proof_bytes=serde_json::to_vec_pretty(&proof)?;let pp=save("artifact-proof.json",&proof_bytes)?;
 let plan=json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[{"source":IMAGE,"name":"retire","sha256":IMAGE_SHA,"mode":365},{"source":pp,"name":"artifact-proof.json","sha256":sha(&proof_bytes),"mode":292}]});
 let bytes=serde_json::to_vec_pretty(&plan)?;let path=save("seal-plan.json",&bytes)?;
 run(Command::new(SEALER).args([&path,"--plan-sha256",&sha(&bytes),"--self-sha256",SEALER_SHA]))?;
 println!("sealed={DEST}; no retirement performed");Ok(())
}
