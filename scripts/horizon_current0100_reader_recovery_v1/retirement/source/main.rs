//! Retire one preserved failed transient reader; no worker or timer mutation.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, path::{Path, PathBuf}, process::Command};
const UNIT: &str = "horizon-failed4-current-accounting-reader-20261104-v1.service";
const IID: &str = "0e271726da824c2bbbad552fc21598ae";
const PID: &str = "3798489";
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2";
const IMAGE_SHA: &str = "d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470";
const SPEC: &str = "/usr/local/lib/jetstreamer/horizon-failed4-current-accounting-reader-plan-actual0030-20261109-v13/spec.json";
const SPEC_SHA: &str = "5ea9b5c5baa6d9e571b971b232fa87379e5a1f1267ce03821b52fa340f46e1ca";
const FAILURE: &str = "/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0030-reader-phase-20261109-v15/94-actual-phase-gated-original-reader-original-outcome.json";
const TIMER: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
const FIELDS: &str = "Id,LoadState,Transient,FragmentPath,InvocationID,MainPID,ControlPID,ExecMainPID,ControlGroup,Job,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,NRestarts,ExecStart,Type,Restart,RemainAfterExit,User,Group,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic";
const ROOT: &str = "/home/sol/.jetstreamer-private/current0030-failed-reader-retirement-qa-20261109-v1";
fn hash(b: &[u8]) -> String {format!("{:x}",Sha256::digest(b))}
fn hex(s: &str,n:usize)->bool{s.len()==n&&s.bytes().all(|x|x.is_ascii_digit()||(b'a'..=b'f').contains(&x))}
fn bytes(p:&Path)->Result<Vec<u8>>{
 ensure!(p.is_absolute()&&p.canonicalize()?==p,"noncanonical metadata path");
 let mut f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(p)?;
 let m=f.metadata()?;ensure!(m.is_file()&&m.uid()==0&&m.nlink()==1&&m.mode()&0o022==0&&m.len()<=128<<20,"metadata custody");
 let mut b=Vec::new();Read::by_ref(&mut f).take((128<<20)+1).read_to_end(&mut b)?;
 let a=f.metadata()?;let z=fs::symlink_metadata(p)?;
 for x in [&a,&z]{ensure!((m.dev(),m.ino(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())==(x.dev(),x.ino(),x.len(),x.mtime(),x.mtime_nsec(),x.ctime(),x.ctime_nsec()),"metadata changed")}
 ensure!(b.len() as u64==m.len(),"metadata length");Ok(b)
}
fn binding(p:&Path)->Result<Value>{Ok(json!({"path":p,"sha256":hash(&bytes(p)?)}))}
fn save(root:&Path,name:&str,v:&Value)->Result<Value>{
 ensure!(!name.contains('/')&&name.ends_with(".json"),"receipt leaf");let p=root.join(name);
 let mut b=serde_json::to_vec_pretty(v)?;b.push(b'\n');
 let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&p)?;
 f.write_all(&b)?;f.set_permissions(fs::Permissions::from_mode(0o444))?;f.sync_all()?;File::open(root)?.sync_all()?;
 Ok(json!({"path":p,"sha256":hash(&b)}))
}
fn parse(raw:&[u8])->Result<Value>{let mut m=serde_json::Map::new();for row in std::str::from_utf8(raw)?.lines(){let(k,v)=row.split_once('=').context("native property")?;ensure!(m.insert(k.into(),json!(v)).is_none(),"duplicate native property");}Ok(Value::Object(m))}
fn command(root:&Path,label:&str,program:&str,args:&[String])->Result<Vec<u8>>{
 let z=Command::new(program).args(args).output()?;ensure!(z.stdout.len()<=4<<20&&z.stderr.len()<=4<<20,"command output bound");
 save(root,&format!("{label}.json"),&json!({"program":program,"args":args,"exit_code":z.status.code(),"stdout_bytes":z.stdout,"stderr_bytes":z.stderr}))?;
 ensure!(z.status.success(),"native command failed: {label}: {}",String::from_utf8_lossy(&z.stderr));Ok(z.stdout)
}
fn show(root:&Path,label:&str,unit:&str)->Result<Value>{parse(&command(root,label,"/usr/bin/systemctl",&["show".into(),unit.into(),format!("--property={FIELDS}")])?)}
fn shape(n:&Value,unit:&str,iid:&str,pid:&str)->Result<()>{
 ensure!(hex(iid,32)&&pid.parse::<u32>()?>1,"owner shape");
 for(k,v)in [("Id",unit),("InvocationID",iid),("ExecMainPID",pid),("LoadState","loaded"),("Transient","yes"),("MainPID","0"),("ControlPID","0"),("ControlGroup",""),("Job",""),("NRestarts","0"),("Restart","no"),("Result","exit-code"),("ExecMainCode","1"),("ExecMainStatus","1"),("ActiveState","failed"),("SubState","failed"),("Type","exec"),("RemainAfterExit","no"),("User","root"),("Group","root")]{ensure!(n[k]==v,"failed transient owner property {k}")}
 ensure!(n["FragmentPath"]==format!("/run/systemd/transient/{unit}"),"transient fragment");
 let start=n["ExecMainStartTimestampMonotonic"].as_str().context("start")?.parse::<u64>()?;
 let end=n["ExecMainExitTimestampMonotonic"].as_str().context("end")?.parse::<u64>()?;ensure!(start>0&&end>=start,"terminal clock");
 ensure!(!Path::new(&format!("/proc/{pid}")).try_exists()?,"original PID exists");
 let cg=PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
 if cg.try_exists()?{ensure!(fs::read_to_string(cg.join("cgroup.procs"))?.trim().is_empty(),"original cgroup has processes")}
 Ok(())
}
fn timer(root:&Path,label:&str)->Result<Value>{
 let n=parse(&command(root,label,"/usr/bin/systemctl",&["show".into(),TIMER.into(),"--property=Id,InvocationID,ActiveState,Unit".into()])?)?;
 ensure!(n["Id"]==TIMER&&n["InvocationID"]=="97aeff8897434ed5ad89dd56c3fb17d1"&&n["ActiveState"]=="active"&&n["Unit"]=="jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service","retained199 timer changed");Ok(n)
}
fn anchor()->Result<PathBuf>{let p=fs::read_link("/proc/2467123/fd/9")?;ensure!(p==Path::new("/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private"),"retained directory FD changed");Ok(p)}
fn journal(root:&Path,unit:&str,iid:&str,n:&Value)->Result<Value>{
 let raw=command(root,"original-PID1-journal","/usr/bin/journalctl",&["--all".into(),"--no-pager".into(),"-ojson".into(),"-n64".into(),"_PID=1".into(),"_UID=0".into(),format!("UNIT={unit}"),format!("INVOCATION_ID={iid}")])?;
 let rows=std::str::from_utf8(&raw)?.lines().map(serde_json::from_str::<Value>).collect::<std::result::Result<Vec<_>,_>>()?;
 let boot=fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().replace('-',"");
 let end=n["ExecMainExitTimestampMonotonic"].as_str().context("exit")?.parse::<u64>()?;
 ensure!(rows.iter().any(|x|x["_PID"]=="1"&&x["_UID"]=="0"&&x["UNIT"]==unit&&x["INVOCATION_ID"]==iid&&x["_BOOT_ID"]==boot&&x["MESSAGE"]==format!("{unit}: Failed with result 'exit-code'.")&&x["__MONOTONIC_TIMESTAMP"].as_str().and_then(|s|s.parse::<u64>().ok()).is_some_and(|t|t>=end)),"same-boot PID1 failure missing");Ok(json!(rows))
}
fn reset(root:&Path,unit:&str,iid:&str,pid:&str,n:&Value)->Result<Value>{
 shape(n,unit,iid,pid)?;let rows=journal(root,unit,iid,n)?;let t=timer(root,"timer-before")?;let a=anchor()?;
 let fragment=Path::new("/run/systemd/transient").join(unit);let f=binding(&fragment)?;
 save(root,"retirement-intent.json",&json!({"native":n,"original_PID1":rows,"fragment":f,"timer":t,"retained_fd9":a,"only_exact_failed_transient_reset":true,"no_payload_or_timer_mutation":true}))?;
 let last=show(root,"before-final-owner-recheck",unit)?;ensure!(&last==n,"failed owner changed before reset");shape(&last,unit,iid,pid)?;
 ensure!(binding(&fragment)?==f&&anchor()?==a,"custody changed before reset");
 command(root,"exact-preserved-transient-reset","/usr/bin/systemctl",&["reset-failed".into(),unit.into()])?;
 let after=show(root,"after-reset-native",unit)?;
 ensure!(after["ActiveState"]=="inactive"&&after["MainPID"].as_str().is_none_or(|p|p=="0")&&after["ControlPID"].as_str().is_none_or(|p|p=="0")&&after["Job"]=="","reset did not drain exact role");
 ensure!(timer(root,"timer-after")?==t&&anchor()?==a,"retained timer or anchor changed");
 save(root,"completion.json",&json!({"schema":"horizon-exact0030-failed-transient-reader-retirement-v1","unit":unit,"original_iid":iid,"original_pid":pid,"original_native":n,"final_native":after,"timer_unchanged":t,"retained_fd9":a,"running_program_sha256":hash(&bytes(&fs::read_link("/proc/self/exe")?)?),"original_failure_and_payloads_preserved":true,"only_failed_transient_reset":true,"replay_launch_authorized":false,"publication_authorized":false,"resource_credit_bytes":0}))
}
fn main()->Result<()>{
 let a=std::env::args().collect::<Vec<_>>();ensure!(a.len()==4&&a[2]=="--self-sha256"&&hex(&a[3],64),"mode --self-sha256 HASH");
 ensure!(unsafe{libc::geteuid()}==0,"Root required");
 let exe=fs::read_link("/proc/self/exe")?;ensure!(hash(&bytes(&exe)?)==a[3],"running executable hash");
 if a[1]=="fail-control"{std::process::exit(1)}
 let root=Path::new(ROOT).join(match a[1].as_str(){"qualify"=>"native-control","retire0030"=>"actual-retirement",_=>anyhow::bail!("unknown mode")});
 fs::create_dir(&root)?;fs::set_permissions(&root,fs::Permissions::from_mode(0o700))?;
 if a[1]=="qualify"{
  let own=std::env::var("INVOCATION_ID")?;ensure!(hex(&own,32),"qualification service IID");let unit=format!("horizon-retire0030-harmless-{own}.service");
  let z=Command::new("/usr/bin/systemd-run").args(["--wait","--pipe","--service-type=exec",&format!("--unit={unit}"),"-p","User=root","-p","Group=root","-p","Restart=no","-p","RemainAfterExit=no","-p","RuntimeMaxSec=15",exe.to_str().context("exe utf8")?,"fail-control","--self-sha256",&a[3]]).output()?;
  save(&root,"intentional-failed-control-original.json",&json!({"exit_code":z.status.code(),"stdout_bytes":z.stdout,"stderr_bytes":z.stderr}))?;ensure!(!z.status.success(),"control must fail");
  let n=show(&root,"failed-control-native",&unit)?;let iid=n["InvocationID"].as_str().context("control iid")?;let pid=n["ExecMainPID"].as_str().context("control pid")?;
  let done=reset(&root,&unit,iid,pid,&n)?;println!("{}",json!({"native_control":done,"program_sha256":a[3]}));
 }else{
  let package=exe.parent().context("image parent")?;
  ensure!(package==Path::new("/usr/local/lib/jetstreamer/horizon-exact0030-transient-reader-retirement-tools-20261109-v1"),"production package scope");
  let proof=package.join("native-control.json");let q:Value=serde_json::from_slice(&bytes(&proof)?)?;
  let seal:Value=serde_json::from_slice(&bytes(&package.join("deployment-seal-receipt.json"))?)?;
  ensure!(seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1"&&seal["sealer_sha256"]=="e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"&&seal["destination"]==package.to_string_lossy().as_ref(),"production normal seal");
  for(name,h)in[("retirement",a[3].clone()),("native-control.json",hash(&bytes(&proof)?))]{ensure!(seal["members"].as_array().context("seal members")?.iter().filter(|x|x["name"]==name&&x["sha256"]==h).count()==1,"seal member binding")}
  ensure!(q["schema"]=="horizon-exact0030-failed-transient-reader-retirement-v1"&&q["running_program_sha256"]==a[3]&&q["only_failed_transient_reset"]==true&&q["unit"].as_str().is_some_and(|s|s.starts_with("horizon-retire0030-harmless-")),"same-image native control absent");
  for(p,h)in[(IMAGE,IMAGE_SHA),(SPEC,SPEC_SHA)]{ensure!(hash(&bytes(Path::new(p))?)==h,"original image/spec changed")}
  let raw=bytes(Path::new(FAILURE))?;let failure:Value=serde_json::from_slice(&raw)?;
  ensure!(failure["program"]=="/usr/bin/systemd-run"&&failure["exit_code"]==1&&failure["wall_finished_at"]==1794184857u64,"original failure outcome changed");
  let e:Vec<u8>=serde_json::from_value(failure["stderr_bytes"].clone())?;ensure!(String::from_utf8(e)?.contains("retained199 guard native changed across readers"),"original error changed");
  let n=show(&root,"original-failed-reader-native",UNIT)?;shape(&n,UNIT,IID,PID)?;
  let expected=format!("{{ path={IMAGE} ; argv[]={IMAGE} read-failed4-current-accounting {SPEC} --spec-sha256 {SPEC_SHA} --self-sha256 {IMAGE_SHA}");
  ensure!(n["ExecStart"].as_str().is_some_and(|s|s.starts_with(&expected)&&s[expected.len()..].starts_with(" ; ignore_errors=no ; ")),"exact reader command changed");
  save(&root,"preserved-original-failure-binding.json",&json!({"failure":binding(Path::new(FAILURE))?,"native_control":binding(&proof)?,"image":binding(Path::new(IMAGE))?,"spec":binding(Path::new(SPEC))?,"running_program_sha256":a[3]}))?;
  let done=reset(&root,UNIT,IID,PID,&n)?;println!("{}",json!({"actual_retirement":done}));
 }Ok(())
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn duplicate_native_fields_reject(){assert!(parse(b"Id=a\nId=b\n").is_err())}
 #[test]fn native_values_remain_strings(){assert_eq!(parse(b"MainPID=0\n").unwrap()["MainPID"],"0")}
 #[test]fn exact_owner_tokens_reject_malformed(){for s in ["","abc","A1234567890123456789012345678901"]{assert!(!hex(s,32))}assert!(hex(IID,32))}
 fn valid()->Value{json!({"Id":UNIT,"InvocationID":IID,"ExecMainPID":PID,"LoadState":"loaded","Transient":"yes","MainPID":"0","ControlPID":"0","ControlGroup":"","Job":"","NRestarts":"0","Restart":"no","Result":"exit-code","ExecMainCode":"1","ExecMainStatus":"1","ActiveState":"failed","SubState":"failed","Type":"exec","RemainAfterExit":"no","User":"root","Group":"root","FragmentPath":format!("/run/systemd/transient/{UNIT}"),"ExecMainStartTimestampMonotonic":"10","ExecMainExitTimestampMonotonic":"20"})}
 #[test]fn original_terminal_shape_accepts(){shape(&valid(),UNIT,IID,PID).unwrap()}
 #[test]fn live_foreign_restarted_and_successful_owners_reject(){for(k,v)in[("MainPID","1"),("ControlPID","1"),("NRestarts","1"),("InvocationID","00000000000000000000000000000000"),("ExecMainPID","42"),("ActiveState","active"),("Result","success"),("Transient","no"),("Id","foreign.service"),("FragmentPath","/etc/systemd/system/foreign.service"),("Job","123"),("ControlGroup","/live")]{let mut n=valid();n[k]=json!(v);assert!(shape(&n,UNIT,IID,PID).is_err(),"{k}")}}
 #[test]fn reversed_or_zero_clock_rejects(){for(k,v)in[("ExecMainStartTimestampMonotonic","0"),("ExecMainExitTimestampMonotonic","1")]{let mut n=valid();n[k]=json!(v);assert!(shape(&n,UNIT,IID,PID).is_err())}}
}
