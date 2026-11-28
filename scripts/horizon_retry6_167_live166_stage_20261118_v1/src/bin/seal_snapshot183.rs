//! Seal the reviewed exact-snapshot183 retirement tool. No unlink or R2 access.
use anyhow::{Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, process::Command};
const REPO:&str="/home/sol/workspace/jetstreamer";
const ROOT:&str="/var/lib/jetstreamer/snapshot183-private-retire-deploy-20261118-v1";
const DEST:&str="/usr/local/lib/jetstreamer/horizon-snapshot183-cleanup-20261118-v1";
const IMAGE:&str="/tmp/snapshot183-retire-target/release/horizon-snapshot183-cleanup";
const IMAGE_SHA:&str="294d6e2363c0170e1a2793219db536fd9b9a0a79557aba2fa8d9e7bf9b126b6b";
const SEALER:&str="/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA:&str="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn run(c:&mut Command)->Result<String>{let o=c.output()?;ensure!(o.status.success(),"{c:?}: {}",String::from_utf8_lossy(&o.stderr));Ok(String::from_utf8(o.stdout)?)}
fn save(leaf:&str,b:&[u8])->Result<String>{let p=format!("{ROOT}/{leaf}");let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(&p)?;f.write_all(b)?;f.sync_all()?;File::open(ROOT)?.sync_all()?;Ok(p)}
fn main()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 let git=|a:&[&str]|run(Command::new("git").arg("-C").arg(REPO).args(a));
 let commit=git(&["rev-parse","HEAD"])?;git(&["merge-base","--is-ancestor",commit.trim(),"origin/account-updates"])?;
 ensure!(git(&["status","--porcelain","--untracked-files=no","--","scripts/horizon_snapshot183_cleanup_20261118_v1","jetstreamer-horizon-observe","scripts/horizon_retry6_167_live166_stage_20261118_v1"])?.is_empty(),"relevant source changed");
 git(&["diff","--exit-code","663c476d","HEAD","--","scripts/horizon_snapshot183_cleanup_20261118_v1","jetstreamer-horizon-observe"])?;
 ensure!(sha(&fs::read(IMAGE)?)==IMAGE_SHA && sha(&fs::read(SEALER)?)==SEALER_SHA,"qualified image or sealer changed");
 fs::create_dir(ROOT)?;fs::set_permissions(ROOT,fs::Permissions::from_mode(0o700))?;
 let mut sources=serde_json::Map::new();
 for p in git(&["ls-files","--","scripts/horizon_snapshot183_cleanup_20261118_v1"])?.lines(){sources.insert(p.into(),json!(sha(&fs::read(format!("{REPO}/{p}"))?)));}
 let proof=json!({"schema":"horizon-snapshot183-private-retire-build-proof-v1","source_commit":commit.trim(),"equivalent_reviewed_source_commit":"663c476d","source_verified_on_fetched_origin":true,"source_paths":sources,"production_sha256":IMAGE_SHA,"retirement_scope":[0],"retained_sealed_source_preserved":true,"tests_and_clippy_passed_in_source_qualification":true,"rebuild_after_observe_rss_change_preserved_exact_image":true,"remote_mutations":false,"r2_mutations":false});
 let proof_bytes=serde_json::to_vec_pretty(&proof)?;let pp=save("artifact-proof.json",&proof_bytes)?;
 let plan=json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[{"source":IMAGE,"name":"retire","sha256":IMAGE_SHA,"mode":365},{"source":pp,"name":"artifact-proof.json","sha256":sha(&proof_bytes),"mode":292}]});
 let bytes=serde_json::to_vec_pretty(&plan)?;let path=save("seal-plan.json",&bytes)?;
 run(Command::new(SEALER).args([&path,"--plan-sha256",&sha(&bytes),"--self-sha256",SEALER_SHA]))?;
 println!("sealed={DEST}; no retirement performed");Ok(())
}
