//! Exact audit-only deployment. Does not start the service or modify R2.
use anyhow::{Context, Result, ensure};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{env,fs::{self,File,OpenOptions},io::Write,os::unix::fs::{OpenOptionsExt,PermissionsExt},path::Path,process::Command};
const ROOT:&str="/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1";
const STATE:&str="/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1";
const DEST:&str="/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v1";
const READERS:&str="/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1";
const REPO:&str="/home/sol/workspace/jetstreamer";
const SEALER:&str="/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA:&str="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn run(c:&mut Command)->Result<String>{let o=c.output()?;ensure!(o.status.success(),"{c:?}: {}",String::from_utf8_lossy(&o.stderr));Ok(String::from_utf8(o.stdout)?)}
fn git(a:&[&str])->Result<String>{run(Command::new("git").arg("-C").arg(REPO).args(a))}
fn save(p:&str,b:&[u8],mode:u32)->Result<()> {let mut f=OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(p)?;f.write_all(b)?;f.sync_all()?;File::open(Path::new(p).parent().unwrap())?.sync_all()?;Ok(())}
fn member(p:&str,n:&str,m:u32)->Result<Value>{Ok(json!({"source":p,"name":n,"sha256":sha(&fs::read(p)?),"mode":m}))}
fn main()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 let a:Vec<_>=env::args().collect();ensure!(a.len()==3,"deploy_audit RUNNER EXPECTED_SHA256");
 ensure!(sha(&fs::read(&a[1])?)==a[2],"runner image changed");
 let commit=git(&["rev-parse","HEAD"])?.trim().to_owned();git(&["merge-base","--is-ancestor",&commit,"origin/account-updates"])?;
 ensure!(git(&["status","--porcelain","--untracked-files=no","--","scripts/horizon_r2_chronological_plugin_audit_20261118_v1","scripts/horizon_retry6_167_live166_stage_20261118_v1"])?.is_empty(),"audit deployment source changed");
 ensure!(sha(&fs::read(SEALER)?)==SEALER_SHA,"sealer changed");
 fs::create_dir(ROOT)?;fs::set_permissions(ROOT,fs::Permissions::from_mode(0o700))?;
 fs::create_dir(STATE)?;fs::set_permissions(STATE,fs::Permissions::from_mode(0o700))?;
 fs::create_dir(READERS)?;fs::set_permissions(READERS,fs::Permissions::from_mode(0o755))?;
 let mut config:Value=serde_json::from_slice(&fs::read(format!("{REPO}/scripts/horizon_r2_chronological_plugin_audit_20261118_v1/config.example.json"))?)?;
 config["state_directory"]=json!(STATE);config["reserve_bytes"]=json!(32u64<<30);
 config["max_archive_bytes"]=json!(16u64<<30);config["build_reserve_bytes"]=json!(16u64<<30);
 config["threads"]=json!(4);config["build_jobs"]=json!(2);
 let config_path=format!("{ROOT}/config.json");save(&config_path,&serde_json::to_vec_pretty(&config)?,0o444)?;
 let env_path=format!("{ROOT}/credentials.env");let mut values=String::new();
 for name in ["HORIZON_ACCESS_KEY_ID","HORIZON_SECRET_ACCESS_KEY","HORIZON_S3_ENDPOINT","SSH_AUTH_SOCK"] {
  let value=env::var(name).with_context(||format!("missing {name}"))?;
  ensure!(!value.is_empty() && !value.contains(['\n','\r','\0','"','\\']),"invalid env value for {name}");
  values.push_str(&format!("{name}=\"{value}\"\n"));
 }
 save(&env_path,values.as_bytes(),0o600)?;
 let service=format!("[Unit]\nDescription=Chronological full Horizon plugin audit of R2 archives\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nUser=sol\nGroup=sol\nUMask=0077\nWorkingDirectory={STATE}\nEnvironmentFile={env_path}\nExecStart={DEST}/audit run {DEST}/config.json\nRestart=on-failure\nRestartSec=1800\nKillMode=control-group\nTimeoutStopSec=30\nCPUQuota=400%\nMemoryHigh=24G\nMemoryMax=32G\nMemorySwapMax=0\nTasksMax=512\nNice=10\nIOWeight=10\nLimitNOFILE=1048576\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={STATE} /home/sol/.cargo\nPrivateDevices=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n[Install]\nWantedBy=multi-user.target\n");
 // Root is needed to account the sealer's root-only temporary directory and
 // to terminate that privileged child's group if an audit resource guard trips.
 let service=service.replace("User=sol\nGroup=sol\n","User=root\nGroup=root\n")
    .replace(" /home/sol/.cargo\n",&format!(" /home/sol/.cargo {READERS}\n"));
 let unit_path=format!("{ROOT}/horizon-r2-chronological-plugin-audit-20261118-v1.service");save(&unit_path,service.as_bytes(),0o444)?;
 let relative="scripts/horizon_r2_chronological_plugin_audit_20261118_v1";
 let files=git(&["ls-files","--",relative])?;ensure!(files.lines().count()>=8,"audit source uncommitted");
 let mut sources=Vec::new();
 for f in files.lines() {let data=fs::read(format!("{REPO}/{f}"))?;let committed=Command::new("git").arg("-C").arg(REPO).args(["show",&format!("{commit}:{f}")]).output()?;ensure!(committed.status.success()&&committed.stdout==data,"uncommitted source {f}");sources.push(json!({"path":f,"sha256":sha(&data)}));}
 let proof=json!({"schema":"horizon-r2-chronological-audit-deployment-v1","source_commit":commit,"source_commit_contained_in_fetched_origin":true,
 "runner_sha256":a[2],"source_files":sources,"state_directory":STATE,"filesystem":"root filesystem only; no campaign scratch allocation",
 "root_reserve_bytes":32u64<<30,"max_archive_bytes":16u64<<30,"build_reserve_bytes":16u64<<30,
 "replay_launch_authorized":false,"r2_mutations_authorized":false,"automatic_larger_archive_admission":false});
 let proof_path=format!("{ROOT}/artifact-proof.json");save(&proof_path,&serde_json::to_vec_pretty(&proof)?,0o444)?;
 let plan=json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[member(&a[1],"audit",0o555)?,member(&config_path,"config.json",0o444)?,member(&unit_path,"horizon-r2-chronological-plugin-audit-20261118-v1.service",0o444)?,member(&proof_path,"artifact-proof.json",0o444)?]});
 let bytes=serde_json::to_vec_pretty(&plan)?;let pp=format!("{ROOT}/seal-plan.json");save(&pp,&bytes,0o400)?;
 run(Command::new(SEALER).args([&pp,"--plan-sha256",&sha(&bytes),"--self-sha256",SEALER_SHA]))?;
 println!("sealed={DEST}; state={STATE}; service not started");Ok(())
}
