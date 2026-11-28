//! Replace the sole pending observation with the same clock plus genuine epoch167.
use anyhow::{Result,ensure};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{fs::{self,File,OpenOptions},io::Write,os::unix::fs::{DirBuilderExt,MetadataExt,OpenOptionsExt},process::Command,time::{SystemTime,UNIX_EPOCH}};
const ROOT:&str="/var/lib/jetstreamer/observe167-join-20261119-v1";
const SOURCE:&str="/usr/local/lib/jetstreamer/horizon-live166-observer-config-0019-20261119-v1/next-observer.json";
const DEST:&str="/usr/local/lib/jetstreamer/horizon-live166167-observer-config-0049-20261119-v1";
const OLD:&str="horizon-observer-root0049-live166-20261119-v1";
const NEW:&str="horizon-observer-root0049-live166167-20261119-v1";
const UNIT:&str="horizon-qualify-167-replacement-local3retry6-20261110-v1.service";
const IID:&str="fdfadeb7b76d4760a37983b402fd2771";
const SEALER:&str="/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA:&str="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn run(c:&mut Command)->Result<String>{let o=c.output()?;ensure!(o.status.success(),"{c:?}: {}",String::from_utf8_lossy(&o.stderr));Ok(String::from_utf8(o.stdout)?)}
fn read(p:&str)->Result<Value>{Ok(serde_json::from_slice(&fs::read(p)?)?)}
fn bind(p:&str)->Result<Value>{Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)}))}
fn save(leaf:&str,v:&Value)->Result<Value>{let p=format!("{ROOT}/{leaf}");let mut f=OpenOptions::new().create_new(true).write(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(&p)?;serde_json::to_writer_pretty(&mut f,v)?;f.write_all(b"\n")?;f.sync_all()?;File::open(ROOT)?.sync_all()?;bind(&p)}
fn native(u:&str)->Result<String>{run(Command::new("/usr/bin/systemctl").args(["show",u,"-pId,ActiveState,SubState,MainPID,InvocationID,NRestarts,Job,NextElapseUSecRealtime"]))}
fn require(s:&str,lines:&[&str])->Result<()>{for l in lines{ensure!(s.lines().any(|r|r==*l),"missing native {l}");}Ok(())}
fn main()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 ensure!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()<1795049365,"scheduled clock already due");
 let admission="/var/lib/jetstreamer/retry6-single167-guarded-launch-20261118-v1/epoch167/ACTUAL_REPLACEMENT_ADMISSION.json";
 let protection="/var/lib/jetstreamer/retry6-single167-guarded-launch-20261118-v1/epoch167/ACTUAL_GUARD_PROTECTION.json";
 let a=read(admission)?;let p=read(protection)?;
 ensure!(a["producer_invocation_id"]==IID && a["fresh_admission_passed"]==true && p["admission"]==bind(admission)? && p["producer_invocation_id"]==IID,"genuine167 admission required");
 let producer=native(UNIT)?;require(&producer,&["ActiveState=active","SubState=running","MainPID=1718241","NRestarts=0",&format!("InvocationID={IID}")])?;
 let log="/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/producer.log";
 let md=fs::symlink_metadata(log)?;ensure!(md.is_file() && md.dev()==64512 && md.ino()==106043387,"167 log changed");
 let scratch="/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-ebf3787fe0720be732ec6d052bcddc6ec5beab557bdae80b8ec95315cb3af8fb/work/root-cohort-167-167/run-1718241-1795049116246585406/scratch";
 ensure!(fs::symlink_metadata(scratch)?.is_dir(),"actual scratch missing");
 let old=native(&format!("{OLD}.timer"))?;require(&old,&["ActiveState=active","SubState=waiting","Job="])?;
 require(&native(&format!("{OLD}.service"))?,&["ActiveState=inactive","MainPID=0","Job="])?;
 let mut config=read(SOURCE)?;ensure!(config["not_before_utc"]=="2026-11-19T00:49:25Z" && config["minimum_interval_seconds"]==1800 && config["replays"].as_array().is_some_and(|v|v.len()==1 && v[0]["range"]=="166"),"foreign pending observer");
 config["replays"].as_array_mut().unwrap().push(json!({"controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":IID,"expected_producer_invocation_id":IID,"range":"167","scratch_path":scratch,"worker_executable_basename":"historical-worker","append_log":{"path":log,"device":md.dev(),"inode":md.ino()}}));
 config["output"]=json!("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root0049-live166167-20261119-v1.json");
 fs::DirBuilder::new().mode(0o700).create(ROOT)?;
 let cb=save("next-observer.json",&config)?;
 let plan=save("seal-plan.json",&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":DEST,"members":[{"source":cb["path"],"name":"next-observer.json","sha256":cb["sha256"],"mode":292}]}))?;
 ensure!(sha(&fs::read(SEALER)?)==SEALER_SHA,"sealer changed");
 run(Command::new(SEALER).args([plan["path"].as_str().unwrap(),"--plan-sha256",plan["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
 save("handoff-intent.json",&json!({"old_config":bind(SOURCE)?,"old_timer_native":old,"new_config":bind(&format!("{DEST}/next-observer.json"))?,"actual167_admission":bind(admission)?,"actual167_protection":bind(protection)?,"cadence_seconds":1800,"sample_created":false}))?;
 ensure!(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()<1795049365 && native(&format!("{OLD}.timer"))?==old,"old timer changed or became due");
 run(Command::new("/usr/bin/systemctl").args(["stop",&format!("{OLD}.timer")]))?;
 require(&native(&format!("{OLD}.timer"))?,&["ActiveState=inactive"])?;
 run(Command::new("/usr/bin/systemd-run").args(["--unit",NEW,"--on-calendar","2026-11-19 00:49:25 UTC","--timer-property=AccuracySec=1s","--property=Type=oneshot","--property=CPUQuota=200%","--property=MemoryMax=2G","--property=TasksMax=128","/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",&format!("{DEST}/next-observer.json")]))?;
 let successor=native(&format!("{NEW}.timer"))?;require(&successor,&["ActiveState=active","SubState=waiting"])?;
 println!("{}",save("completion.json",&json!({"old_timer_stopped":true,"new_timer_native":successor,"new_config":bind(&format!("{DEST}/next-observer.json"))?,"same_clock":true,"replay_mutations":false,"remote_mutations":false}))?);Ok(())
}
