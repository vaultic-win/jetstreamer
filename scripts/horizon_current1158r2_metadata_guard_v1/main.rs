//! Single original metadata command behind the existing natural guard-window gate.
//! No R2, controller/guard mutation, new observation loop or replay authority.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
const GUARD: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service";
const TIMER: &str = "jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
const TIMER_IID: &str = "97aeff8897434ed5ad89dd56c3fb17d1";
const CONTROLLER: &str = "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service";
const CONTROL_IID: &str = "dbf49bb1b72c42c584f2d3ac94259cb8";
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainStatus,Result,NRestarts,Job,TimersMonotonic,Unit";
const SAMPLE_UNIX: u64 = 1_794_052_689;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Native { fields: BTreeMap<String, String>, timers: Vec<(String, u64, u64)> }
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> { v.get(key).and_then(Value::as_str).with_context(|| format!("missing string {key}")) }
fn get<'a>(v: &'a Native, key: &str) -> Result<&'a str> { v.fields.get(key).map(String::as_str).with_context(|| format!("missing native property {key}")) }
fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn hash_file(path: &Path) -> Result<String> { let mut f=File::open(path)?; let mut d=Sha256::new(); let mut b=[0u8;65536]; loop { let n=f.read(&mut b)?; if n==0 {break;} d.update(&b[..n]); } Ok(format!("{:x}", d.finalize())) }
fn iid(value: &str) -> bool { value.len()==32 && value.bytes().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)) }
fn duration_us(s: &str) -> Result<u64> {
 let mut total=0u64; ensure!(!s.is_empty(), "empty duration");
 for word in s.split_whitespace() {
  let p=word.find(|c:char| !(c.is_ascii_digit() || c=='.')).context("duration unit missing")?;
  let (number,unit)=word.split_at(p);
  let factor=match unit {"us"=>1u64,"ms"=>1000,"s"=>1_000_000,"min"=>60_000_000,"h"=>3_600_000_000,"d"=>86_400_000_000,"w"=>604_800_000_000,_=>bail!("unqualified duration unit {unit}")};
  let parts:Vec<_>=number.split('.').collect(); ensure!(parts.len()<=2 && !parts[0].is_empty(), "bad decimal duration");
  let whole=parts[0].parse::<u64>()?.checked_mul(factor).context("duration overflow")?;
  let fraction=if parts.len()==2 {ensure!(!parts[1].is_empty() && parts[1].len()<=9,"bad duration precision");let num=parts[1].parse::<u64>()?.checked_mul(factor).context("fraction overflow")?;let den=10u64.pow(parts[1].len() as u32);ensure!(num.is_multiple_of(den),"duration not integral microseconds");num/den} else {0};
  total=total.checked_add(whole).and_then(|x|x.checked_add(fraction)).context("sum overflow")?;
 } Ok(total)
}
fn timer_events(s: &str) -> Result<Vec<(String,u64,u64)>> {
 let mut rest=s.trim(); let mut result=Vec::new();
 while !rest.is_empty() {
  ensure!(rest.starts_with('{'),"timer event missing brace"); let end=rest.find('}').context("timer event missing close")?;
  let inner=&rest[1..end]; let (first,last)=inner.split_once(';').context("timer event missing separator")?;
  ensure!(!last.contains(';'),"extra timer component"); let (kind,interval)=first.trim().split_once('=').context("timer kind missing")?;
  ensure!(matches!(kind,"OnUnitActiveUSec"|"OnActiveUSec"),"unexpected timer kind");
  let (name,at)=last.trim().split_once('=').context("timer elapse missing")?;ensure!(name=="next_elapse","unknown elapse key");
  result.push((kind.to_owned(),duration_us(interval.trim())?,duration_us(at.trim())?));rest=rest[end+1..].trim();
 } Ok(result)
}
fn parse_native(raw: &str) -> Result<Native> {
 let mut fields=BTreeMap::new();let mut timers=Vec::new();
 for line in raw.lines() { let (key,value)=line.split_once('=').context("native line missing equals")?; if key=="TimersMonotonic" {timers.extend(timer_events(value)?);} else {ensure!(fields.insert(key.to_owned(),value.to_owned()).is_none(),"duplicate native scalar {key}");} }
 Ok(Native{fields,timers})
}
fn command(program: &str, args: &[String], seconds: u64) -> Result<Output> {
 // Bound only the spawned metadata CLI. Never stop or reset its managed systemd unit.
 Command::new("/usr/bin/timeout").arg("--signal=TERM").arg(seconds.to_string()).arg(program).args(args).env_remove("SYSTEMD_HOST").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env("LC_ALL","C").output().context("spawn bounded metadata command")
}
fn native(unit: &str, allow_absent: bool) -> Result<Native> {
 let o=command("/usr/bin/systemctl", &["show".into(),unit.into(),"--no-pager".into(),format!("--property={FIELDS}")],5)?;
 let n=parse_native(std::str::from_utf8(&o.stdout)?)?;ensure!(get(&n,"Id")?==unit,"wrong native ID");
 if !o.status.success() {ensure!(allow_absent && get(&n,"LoadState")?=="not-found" && get(&n,"ActiveState")?=="inactive" && get(&n,"InvocationID")?.is_empty() && get(&n,"MainPID")?=="0" && get(&n,"ControlPID")?=="0" && get(&n,"Job")?.is_empty(),"native lookup failed or ambiguous");}
 Ok(n)
}
fn native_json(n:&Native)->Value {json!({"fields":n.fields,"TimersMonotonic_entries":n.timers})}
fn clock(clockid: libc::clockid_t) -> Result<u64> { let mut t=libc::timespec{tv_sec:0,tv_nsec:0}; ensure!(unsafe{libc::clock_gettime(clockid,&mut t)}==0,"clock_gettime failed");ensure!(t.tv_sec>=0 && t.tv_nsec>=0,"negative clock"); (t.tv_sec as u64).checked_mul(1_000_000).and_then(|x|x.checked_add(t.tv_nsec as u64/1000)).context("clock overflow") }
fn fresh() -> Result<()> {let now=clock(libc::CLOCK_REALTIME)?/1_000_000;ensure!(now>=SAMPLE_UNIX && now-SAMPLE_UNIX<1800,"2058 sample stale; no launch");Ok(())}
fn same_meta(a:&fs::Metadata,b:&fs::Metadata)->bool {a.dev()==b.dev() && a.ino()==b.ino() && a.uid()==b.uid() && a.gid()==b.gid() && a.mode()==b.mode() && a.nlink()==b.nlink() && a.len()==b.len() && a.mtime()==b.mtime() && a.mtime_nsec()==b.mtime_nsec() && a.ctime()==b.ctime() && a.ctime_nsec()==b.ctime_nsec()}
fn read_bound(binding:&Value)->Result<Value> {
 let p=Path::new(text(binding,"path")?);let meta=fs::symlink_metadata(p)?;ensure!(p.is_absolute() && meta.is_file() && meta.uid()==0 && meta.nlink()==1 && meta.len()<=4_194_304 && fs::canonicalize(p)?==p,"unsafe bound metadata");
 let mut f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(p)?;ensure!(same_meta(&meta,&f.metadata()?),"metadata changed before open");let mut bytes=Vec::new();f.read_to_end(&mut bytes)?;ensure!(same_meta(&meta,&f.metadata()?) && same_meta(&meta,&fs::symlink_metadata(p)?) && sha(&bytes)==text(binding,"sha256")?,"bound metadata changed or digest mismatch");Ok(serde_json::from_slice(&bytes)?)
}
fn save(dir:&Path,name:&str,value:&Value)->Result<()> {ensure!(!name.contains('/') && !name.contains(".."),"unsafe receipt name");let p=dir.join(name);let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(p)?;serde_json::to_writer_pretty(&mut f,value)?;f.write_all(b"\n")?;f.sync_all()?;File::open(dir)?.sync_all()?;Ok(())}
fn controller()->Result<Native> {
 let n=native(CONTROLLER,false)?;ensure!(get(&n,"InvocationID")?==CONTROL_IID && get(&n,"MainPID")?=="2467123" && get(&n,"NRestarts")?=="0","original199 controller changed");
 ensure!(fs::read_link("/proc/2467123/fd/9")?==Path::new("/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private"),"original199 FD9 changed");
 let s=fs::read_to_string("/proc/2467123/stat")?;let tail=s.rsplit_once(')').context("proc stat malformed")?.1;let ticks=tail.split_whitespace().nth(19).context("proc ticks missing")?.parse::<u64>()?;ensure!(ticks==200_799_001,"original199 PID recycled");Ok(n)
}
fn idle_guard(n:&Native)->Result<bool> {Ok(get(n,"ActiveState")?=="inactive" && get(n,"SubState")?=="dead" && get(n,"MainPID")?=="0" && get(n,"ControlPID")?=="0" && get(n,"ExecMainStatus")?=="0" && get(n,"NRestarts")?=="0" && get(n,"Result")?=="success" && get(n,"Job")?.is_empty() && iid(get(n,"InvocationID")?))}
fn timer_policy(n:&Native)->Result<()> {
 ensure!(get(n,"Id")?==TIMER && get(n,"InvocationID")?==TIMER_IID && get(n,"ActiveState")?=="active" && matches!(get(n,"SubState")?,"waiting"|"running") && get(n,"Unit")?==GUARD && get(n,"Job")?.is_empty(),"original timer identity, state or target changed: {:?}",n);
 let mut kinds:Vec<_>=n.timers.iter().map(|x|(x.0.as_str(),x.1)).collect();kinds.sort_unstable();ensure!(kinds==vec![("OnActiveUSec",1_000_000),("OnUnitActiveUSec",30_000_000)],"timer event policy changed");Ok(())
}
fn timer_wait_only(n:&Native)->Result<bool> {timer_policy(n)?;Ok(get(n,"SubState")?=="running")}
fn next_timer(n:&Native,now:u64)->Result<u64> {
 timer_policy(n)?;ensure!(get(n,"SubState")?=="waiting","running original timer is observation only, never a launch window");
 n.timers.iter().map(|x|x.2).filter(|x|*x>now).min().context("no future original timer event")
}

fn window(dir:&Path,label:&str)->Result<Value> {
 let start=Instant::now();let mut samples=Vec::new();
 while start.elapsed()<Duration::from_secs(65) {
  fresh()?;let g=native(GUARD,false)?;let t=native(TIMER,false)?;let now=clock(libc::CLOCK_MONOTONIC)?;if timer_wait_only(&t)? {samples.push(json!({"guard":native_json(&g),"timer":native_json(&t),"sampled_monotonic_usec":now,"wait_reason":"original guard is running; no launch authority"}));std::thread::sleep(Duration::from_millis(500));continue;}let next=next_timer(&t,now)?;
  samples.push(json!({"guard":native_json(&g),"timer":native_json(&t),"sampled_monotonic_usec":now,"absolute_next_monotonic_usec":next,"remaining_usec":next-now}));
  if idle_guard(&g)? && next-now>=12_000_000 {
   let c=controller()?;ensure!(native(GUARD,false)?==g && native(TIMER,false)?==t,"native gate identity changed during recheck");let at=clock(libc::CLOCK_MONOTONIC)?;ensure!(next>=at && next-at>=10_000_000,"natural guard window consumed before launch");
   let value=json!({"schema":"horizon-original-completed-guard-window-preflight-v3-rust","bounded_wait_metadata":samples,"guard":native_json(&g),"timer":native_json(&t),"controller":native_json(&c),"absolute_next_monotonic_usec":next,"no_guard_timer_or_controller_mutation":true});save(dir,&format!("{label}-COMPLETED_GUARD_WINDOW_PREFLIGHT_RUST.json"),&value)?;return Ok(value);
  }
  std::thread::sleep(Duration::from_secs(1));
 } bail!("natural completed guard window unavailable; no command launched")
}
fn allowed_unit(unit:&str)->bool {matches!(unit,"horizon-postreplay145-current1158r2-fleet-20261107-v1.service"|"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capability-20261107-v1.service"|"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service")}
fn no_block_transport(logical:&[String],unit:&str)->Result<Vec<String>> {
 ensure!(allowed_unit(unit),"only exact fresh2058 metadata roles; original1058fleet and every previous target are excluded");
 ensure!(logical.first().map(String::as_str)==Some("/usr/bin/systemd-run"),"wrong transport program");
 let positions:Vec<_>=logical.iter().enumerate().filter_map(|(i,x)|(x=="--no-block").then_some(i)).collect();
 ensure!(positions.is_empty() || positions==vec![1],"duplicate or noncanonical no-block transport");
 let mut actual=logical.to_vec();if positions.is_empty(){actual.insert(1,"--no-block".to_owned());}
 ensure!(actual.iter().filter(|x|x.as_str()=="--no-block").count()==1,"transport cardinality");Ok(actual)
}
// Exact combined helper after full QA and normal production seal.
const QUALIFIED_SHARED_HELPER_BINDING: Option<(&str,&str)> = Some(("/usr/local/lib/jetstreamer/horizon-live145-fleet-custody-current-helper-tools-20261107-v1/jetstreamer-r2","be589f314c1e5f2ff6799800d39ca02e348c8e2e36779f6bdaf247d56d245405")); // Root must bind the actual newly qualified normally sealed helper; never inherit6739 or37367.
fn checked_shared_binding(pin:Option<(&'static str,&'static str)>)->Result<(&'static str,&'static str)> {
 let (path,digest)=pin.context("UNRESOLVED exact combined shared helper program/digest; fleet launch denied")?;
 ensure!(path.starts_with("/usr/local/lib/jetstreamer/") && Path::new(path).file_name().and_then(|x|x.to_str())==Some("jetstreamer-r2"),"shared helper path outside exact normal-seal namespace");
 ensure!(digest.len()==64 && digest.bytes().all(|x|x.is_ascii_digit()||(b'a'..=b'f').contains(&x)),"shared helper digest malformed");Ok((path,digest))
}
const QUALIFIED_FRAME_BINDING: Option<(&str,&str)> = Some(("/usr/local/lib/jetstreamer/horizon-live145-census-frame-cli-tools-20261107-v1/jetstreamer-horizon-frame","7d4888bf5c5b3559c9d2c49846675ebdd8b09e699d1a681b6d388704e48a0a49"));
fn checked_frame_binding(pin:Option<(&'static str,&'static str)>)->Result<(&'static str,&'static str)> {
 let (path,digest)=pin.context("UNRESOLVED independently qualified Frame successor")?;
 ensure!(path.starts_with("/usr/local/lib/jetstreamer/") && Path::new(path).file_name().and_then(|s|s.to_str())==Some("jetstreamer-horizon-frame"),"Frame normal-seal namespace differs");
 ensure!(digest.len()==64 && digest.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"Frame digest malformed");Ok((path,digest))
}
fn verified_argv(plan:&Value)->Result<(Vec<String>,String)> {
 ensure!(text(plan,"schema")?=="horizon-original-completed-guard-window-native-argv-plan-v1" && plan["not_launch_authority"]==true,"unqualified argv plan");
 let av:Vec<String>=plan["argv"].as_array().context("argv missing")?.iter().map(|x|x.as_str().map(str::to_owned).context("non-string argv")).collect::<Result<_>>()?;
 ensure!(av.first().map(String::as_str)==Some("/usr/bin/systemd-run") && av.iter().all(|x|!x.contains('\0') && !x.starts_with("--host") && !x.starts_with("--machine") && x!="--user"),"unsafe command target");
 let names:Vec<_>=av.iter().filter_map(|x|x.strip_prefix("--unit=")).collect();ensure!(names.len()==1,"wrong unit argument count");let unit=if names[0].ends_with(".service"){names[0].to_owned()}else{format!("{}.service",names[0])};ensure!(allowed_unit(&unit),"unit outside exact metadata scope");
 let i=av.iter().position(|x|x=="--plan-sha256").context("plan hash missing")?;ensure!(i>0 && i+1<av.len(),"bad plan hash shape");ensure!(hash_file(Path::new(&av[i-1]))?==av[i+1],"native plan digest mismatch");

 let (program,digest)=if unit.contains("fleet-"){checked_shared_binding(QUALIFIED_SHARED_HELPER_BINDING)?}else{checked_frame_binding(QUALIFIED_FRAME_BINDING)?};
 ensure!(av.iter().filter(|x|x.as_str()==program).count()==1 && hash_file(Path::new(program))?==digest,"native executable binding mismatch");Ok((av,unit))
}

const DATA_UNIT: &str = "horizon-epoch183-ended-DATA-select-20261105-v1.service";
const DATA_PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-completed145-ended183-DATA-selector-tools-20261106-v3/ended183-data";
const DATA_SHA: &str = "4835b9eb84a290c2f938556e0f5235bd92d6be201677543374c94f1abf8a58ae";
fn mode_allowed(mode:&str)->bool {matches!(mode,"run-original"|"run-original-data")}
fn checked_data_transport(av:&[String])->Result<()> {
 ensure!(av.first().map(String::as_str)==Some("/usr/bin/systemd-run") && av.iter().all(|x|!x.contains('\0') && !x.starts_with("--host") && !x.starts_with("--machine") && x!="--user"),"unsafe DATA command target");
 for token in ["--wait","--pipe","--service-type=exec"] {ensure!(av.iter().filter(|x|x.as_str()==token).count()==1,"DATA exact synchronous exec transport differs");}
 ensure!(av.iter().all(|x|!x.starts_with("--no-block") && !x.contains("RemainAfterExit") && !x.starts_with("--collect") && !x.starts_with("--scope")),"DATA cannot use no-block, collect, scope or retained oneshot transport");
 let service_types:Vec<_>=av.iter().filter(|x|x.starts_with("--service-type")).collect();ensure!(service_types.len()==1,"DATA conflicting service type");
 let names:Vec<_>=av.iter().filter_map(|x|x.strip_prefix("--unit=")).collect();ensure!(names.len()==1 && (names[0]==DATA_UNIT || format!("{}.service",names[0])==DATA_UNIT),"DATA fixed native role differs");
 let programs:Vec<_>=av.iter().enumerate().filter_map(|(i,x)|(x==DATA_PROGRAM).then_some(i)).collect();ensure!(programs.len()==1,"DATA exact qualified program differs");
 let mut cursor=1usize;let end=programs[0];let mut properties=std::collections::BTreeSet::new();
 while cursor<end {
  let token=&av[cursor];
  if token=="--wait" || token=="--pipe" || token=="--service-type=exec" || token.starts_with("--unit=") {cursor+=1;continue;}
  ensure!(token=="-p" && cursor+1<end,"undeclared DATA systemd transport token");let property=&av[cursor+1];let (key,value)=property.split_once('=').context("DATA property shape")?;
  ensure!(properties.insert(key.to_owned()),"duplicate DATA native property");
  ensure!(matches!((key,value),("User","root")|("Group","root")|("Restart","no")|("MemoryAccounting","yes")|("MemoryHigh","2G")|("MemoryMax","2G")|("MemorySwapMax","0")|("CPUQuota","100%")|("TasksMax","512")|("RuntimeMaxSec","600")|("TimeoutStopSec","15")|("PrivateNetwork","yes")|("ProtectSystem","strict")|("ProtectHome","read-only")|("NoNewPrivileges","yes")|("CapabilityBoundingSet","CAP_DAC_OVERRIDE CAP_SYS_PTRACE")|("AmbientCapabilities","CAP_DAC_OVERRIDE CAP_SYS_PTRACE")|("TemporaryFileSystem","/tmp:ro /var/tmp:ro")) || (key=="ReadWritePaths" && value.starts_with("/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1/")),"undeclared DATA native property/value");cursor+=2;
 }
 let i=programs[0];ensure!(av.len()==i+9 && av[i+1]=="select" && av[i+3]=="--plan-sha256" && av[i+5]=="--self-sha256" && av[i+6]==DATA_SHA && av[i+7]=="--output","DATA exact native protocol or image digest differs");
 Ok(())
}
fn checked_data_lineage(observer:&Value,memory:&Value,policy:&Value)->Result<()> {
 ensure!(memory["selection"]["request"]["current"]["observer"]==*observer && policy["current"]["observer"]==*observer,"DATA actual memory/policy observer crossed");Ok(())
}
fn verified_data_argv(plan:&Value,observer:&Value)->Result<Vec<String>> {
 ensure!(text(plan,"schema")?=="horizon-original-completed-guard-window-native-argv-plan-v1" && plan["not_launch_authority"]==true,"unqualified DATA argv plan");
 let av=plan["argv"].as_array().context("DATA argv missing")?.iter().map(|x|x.as_str().map(str::to_owned).context("non-string DATA argv")).collect::<Result<Vec<_>>>()?;checked_data_transport(&av)?;
 let i=av.iter().position(|x|x==DATA_PROGRAM).context("DATA program missing")?;
 ensure!(hash_file(Path::new(DATA_PROGRAM))?==DATA_SHA,"DATA running-program input hash differs");
 let input=read_bound(&json!({"path":av[i+2],"sha256":av[i+4]}))?;
 let memory=read_bound(&input["memory_selection"])?;let policy=read_bound(&input["data_policy"])?;checked_data_lineage(observer,&memory,&policy)?;
 let output=Path::new("/var/lib/jetstreamer/horizon-ended183-DATA-selection-v1").join(text(observer,"sha256")?);
 ensure!(av.iter().filter(|x|x.as_str()==format!("ReadWritePaths={}",output.display())).count()==1,"DATA exact write scope missing");
 ensure!(input["output_directory"]==json!(output) && Path::new(&av[i+8])==output.join("selection.json") && !Path::new(&av[i+8]).exists(),"DATA output is occupied or outside current observer namespace");
 Ok(av)
}
fn completed_data(n:&Native)->Result<()> {
 ensure!(get(n,"Id")?==DATA_UNIT && get(n,"MainPID")?=="0" && get(n,"ControlPID")?=="0" && get(n,"Job")?.is_empty() && get(n,"NRestarts")?=="0" && get(n,"ExecMainStatus")?=="0" && get(n,"Result")?=="success" && get(n,"ActiveState")?=="inactive" && get(n,"SubState")?=="dead","DATA original exec has not completed successfully and drained");Ok(())
}
fn run_data(p:&Path,label:&str,binding:&Value,plan:&Value,observer:&Value)->Result<()> {
 let av=verified_data_argv(plan,observer)?;let before=native(DATA_UNIT,true)?;
 ensure!(get(&before,"ActiveState")?=="inactive" && get(&before,"InvocationID")?.is_empty() && get(&before,"MainPID")?=="0" && get(&before,"ControlPID")?=="0" && get(&before,"Job")?.is_empty(),"DATA target not pristine dormant");
 let preflight=window(p,label)?;fresh()?;save(p,&format!("{label}-PREWRITTEN_ORIGINAL_ARGV.json"),&json!({"argv":av,"logical_argv":av,"exact_synchronous_exec_transport_unchanged":true,"plan":binding,"before":native_json(&before),"preflight":preflight,"no_retry":true}))?;
 let deadline=preflight["absolute_next_monotonic_usec"].as_u64().context("DATA preflight next missing")?;
 ensure!(native_json(&native(GUARD,false)?)==preflight["guard"] && native_json(&native(TIMER,false)?)==preflight["timer"],"original guard changed immediately before DATA command");
 let now=clock(libc::CLOCK_MONOTONIC)?;ensure!(deadline>now && deadline-now>=10_000_000,"original DATA window consumed before command; no launch");
 let o=command(&av[0],&av[1..],610)?;
 save(p,&format!("{label}-ORIGINAL_EXECUTION.json"),&json!({"code":o.status.code(),"stdout":String::from_utf8_lossy(&o.stdout),"stderr":String::from_utf8_lossy(&o.stderr),"argv":av,"metadata_cli_timeout_seconds":610,"no_retry":true}))?;
 ensure!(o.status.success(),"original DATA command failed; preserve attempt");let terminal=native(DATA_UNIT,false)?;completed_data(&terminal)?;
 let cg=Path::new("/sys/fs/cgroup/system.slice").join(DATA_UNIT);if cg.exists(){ensure!(fs::read_to_string(cg.join("cgroup.procs"))?.trim().is_empty() && fs::read_to_string(cg.join("cgroup.events"))?.lines().any(|x|x=="populated 0"),"original DATA cgroup still populated");}
 save(p,&format!("{label}-COMPLETED_NATIVE.json"),&json!({"native":terminal.fields,"original_stdout_and_stderr":format!("{label}-ORIGINAL_EXECUTION.json"),"invocation_identity_and_original_PID1_must_come_from_actual_DATA_receipt":true,"current_native_IID_may_be_cleared":true,"no_original_invocation_invented":true,"no_resource_credit":true}))?;controller()?;
 println!("{}",json!({"unit":DATA_UNIT,"original_command_completed":true,"original_invocation_identity_pending_actual_DATA_receipt_and_PID1":true,"no_resource_credit":true}));Ok(())
}

fn run()->Result<()> {
 ensure!(unsafe{libc::geteuid()}==0,"root required");let args:Vec<_>=std::env::args().collect();ensure!(args.len()==8 && mode_allowed(&args[1]) && args[4]=="--spec-sha256" && args[6]=="--self-sha256","usage: run-original|run-original-data LABEL PLAN --spec-sha256 SHA --self-sha256 SHA");
 ensure!(hash_file(Path::new("/proc/self/exe"))?==args[7],"running executable digest mismatch");let label=&args[2];ensure!(!label.is_empty() && label.len()<=80 && label.bytes().all(|x|x.is_ascii_alphanumeric() || x==b'_' || x==b'-'),"bad label");
 let p=PathBuf::from("/home/sol/.jetstreamer-private/native1158r2-live145-frame-workflow-source-20261107-v1/runtime");let m=fs::symlink_metadata(&p)?;ensure!(m.is_dir() && m.uid()==0 && m.mode()&0o777==0o700 && fs::canonicalize(&p)?==p,"unsafe private output directory");
 let binding=json!({"path":args[3],"sha256":args[5]});let plan=read_bound(&binding)?;let request=read_bound(&plan["request"])?;let observer=read_bound(&request["observer"])?;ensure!(text(&observer,"recorded_at_utc")?=="2026-11-07T11:58:09Z","wrong observation sample");fresh()?;
 if args[1]=="run-original-data" {return run_data(&p,label,&binding,&plan,&request["observer"]);}
 let (logical_av,unit)=verified_argv(&plan)?;let av=no_block_transport(&logical_av,&unit)?;let before=native(&unit,true)?;ensure!(get(&before,"ActiveState")?=="inactive" && get(&before,"InvocationID")?.is_empty() && get(&before,"MainPID")?=="0" && get(&before,"ControlPID")?=="0" && get(&before,"Job")?.is_empty(),"target not pristine dormant");
 let preflight=window(&p,label)?;fresh()?;save(&p,&format!("{label}-PREWRITTEN_ORIGINAL_ARGV.json"),&json!({"argv":av,"logical_argv":logical_av,"no_block_transport_preserves_all_logical_tokens":true,"plan":binding,"before":native_json(&before),"preflight":preflight,"no_retry":true}))?;
 let gate_next=preflight["absolute_next_monotonic_usec"].as_u64().context("preflight next missing")?; ensure!(native_json(&native(GUARD,false)?)==preflight["guard"] && native_json(&native(TIMER,false)?)==preflight["timer"],"original guard changed immediately before command"); let gate_now=clock(libc::CLOCK_MONOTONIC)?; ensure!(gate_next>gate_now && gate_next-gate_now>=1_000_000,"original window consumed before command; no launch");
 let o=command(&av[0],&av[1..],15)?;save(&p,&format!("{label}-ORIGINAL_EXECUTION.json"),&json!({"code":o.status.code(),"stdout":String::from_utf8_lossy(&o.stdout),"stderr":String::from_utf8_lossy(&o.stderr),"argv":av}))?;ensure!(o.status.success(),"original command failed; preserve attempt");
 let start=Instant::now();let mut beat=Instant::now();let terminal=loop {let n=native(&unit,false)?;if get(&n,"ActiveState")?=="active" && get(&n,"SubState")?=="exited"{break n;}ensure!(matches!(get(&n,"ActiveState")?,"activating"|"active") && start.elapsed()<Duration::from_secs(310),"original native failed or bounded wait expired; never retry");if beat.elapsed()>=Duration::from_secs(60){eprintln!("metadata native wait unit={unit} elapsed={}s; awaiting original PID1 completion",start.elapsed().as_secs());beat=Instant::now();}std::thread::sleep(Duration::from_secs(1));};
 ensure!(get(&terminal,"MainPID")?=="0" && get(&terminal,"ControlPID")?=="0" && get(&terminal,"NRestarts")?=="0" && get(&terminal,"ExecMainStatus")?=="0" && get(&terminal,"Result")?=="success" && get(&terminal,"Job")?.is_empty() && iid(get(&terminal,"InvocationID")?),"terminal native invalid");
 let j=command("/usr/bin/journalctl", &["--all".into(),"--no-pager".into(),"--output=json".into(),"-u".into(),unit.clone()],15)?;ensure!(j.status.success(),"original journal lookup failed");let rows:Vec<Value>=std::str::from_utf8(&j.stdout)?.lines().map(serde_json::from_str).collect::<std::result::Result<_,_>>()?;
 ensure!(rows.iter().any(|x|x["_PID"]=="1" && x["UNIT"]==unit && x["INVOCATION_ID"]==get(&terminal,"InvocationID").unwrap_or("") && x["JOB_RESULT"]=="done"),"original PID1 completion missing");
 let cg=Path::new("/sys/fs/cgroup/system.slice").join(&unit);if cg.exists(){ensure!(fs::read_to_string(cg.join("cgroup.procs"))?.trim().is_empty() && fs::read_to_string(cg.join("cgroup.events"))?.lines().any(|x|x=="populated 0"),"original cgroup still populated");}
 save(&p,&format!("{label}-PID1.json"),&json!(rows))?;save(&p,&format!("{label}-COMPLETED_NATIVE.json"),&json!(terminal.fields))?;controller()?;println!("{}",json!({"unit":unit,"original_invocation_id":get(&terminal,"InvocationID")?,"no_resource_credit":true}));Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("guard-window original attempt failed: {e:#}");std::process::exit(1);}}
#[cfg(test)] mod tests {
 use super::*;
 fn timer()->Native {parse_native(&format!("Id={TIMER}\nInvocationID={TIMER_IID}\nActiveState=active\nSubState=waiting\nUnit={GUARD}\nJob=\nTimersMonotonic={{ OnUnitActiveUSec=30s ; next_elapse=100s }}\nTimersMonotonic={{ OnActiveUSec=1s ; next_elapse=1s }}\n")).unwrap()}
 #[test]fn decimal_duration(){assert_eq!(duration_us("1h 2min 3.5s").unwrap(),3_723_500_000);}
 #[test]fn exact_microseconds(){assert_eq!(duration_us("0.000001s").unwrap(),1);}
 #[test]fn unknown_duration(){for x in ["infinity","n/a","-1s","1fortnight","1"]{assert!(duration_us(x).is_err(),"{x}");}}
 #[test]fn fractional_microsecond_rejects(){assert!(duration_us("0.0000001s").is_err());}
 #[test]fn overflow_duration_rejects(){assert!(duration_us("18446744073709551615w").is_err());}
 #[test]fn repeated_timer_fields_preserved(){assert_eq!(timer().timers.len(),2);}
 #[test]fn events_one_line(){assert_eq!(timer_events("{ OnActiveUSec=1s ; next_elapse=1s } { OnUnitActiveUSec=30s ; next_elapse=100s }").unwrap().len(),2);}
 #[test]fn duplicate_scalar_rejects(){assert!(parse_native("Id=one\nId=two\n").is_err());}
 #[test]fn malformed_event_rejects(){for x in ["garbage","{ missing }","{ OnActiveUSec=1s ; garbage=2s }","{ OnActiveUSec=1s ; next_elapse=2s ; extra=3s }"]{assert!(timer_events(x).is_err());}}
 #[test]fn policy_unknown_timer_rejects(){assert!(timer_events("{ OnBootUSec=1s ; next_elapse=2s }").is_err());}
 #[test]fn chooses_future_event(){assert_eq!(next_timer(&timer(),2_000_000).unwrap(),100_000_000);}
 #[test]fn expired_timer_rejects(){assert!(next_timer(&timer(),100_000_000).is_err());}
 #[test]fn timer_identity_change_rejects(){let mut n=timer();n.fields.insert("InvocationID".into(),"00000000000000000000000000000000".into());assert!(next_timer(&n,2_000_000).is_err());}
 #[test]fn timer_schedule_change_rejects(){let mut n=timer();n.timers[0].1=60_000_000;assert!(next_timer(&n,2_000_000).is_err());}
 #[test]fn missing_native_property_rejects(){let mut n=timer();n.fields.remove("Unit");assert!(next_timer(&n,2_000_000).is_err());}
 #[test]fn iid_exact_shape(){assert!(iid(CONTROL_IID));for s in ["","123","DBF49BB1B72C42C584F2D3AC94259CB8","dbf49bb1b72c42c584f2d3ac94259cb/"]{assert!(!iid(s));}}

 #[test]fn frame_transport_adds_no_block_once(){let a=vec!["/usr/bin/systemd-run".into(),"--unit=frame".into()];let r=no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service").unwrap();assert_eq!(r,vec!["/usr/bin/systemd-run","--no-block","--unit=frame"]);}
 #[test]fn existing_canonical_transport_idempotent(){let a=vec!["/usr/bin/systemd-run".into(),"--no-block".into(),"--unit=frame".into()];assert_eq!(no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capability-20261107-v1.service").unwrap(),a);}
 #[test]fn duplicate_no_block_rejected(){let a=vec!["/usr/bin/systemd-run".into(),"--no-block".into(),"--no-block".into()];assert!(no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service").is_err());}
 #[test]fn noncanonical_existing_transport_rejected(){let a=vec!["/usr/bin/systemd-run".into(),"--unit=frame".into(),"--no-block".into()];assert!(no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service").is_err());}
 #[test]fn original_fleet_never_admitted_by_r3(){let a=vec!["/usr/bin/systemd-run".into()];assert!(no_block_transport(&a,"horizon-postreplay145-current0458-fleet-20261106-v1.service").is_err());}
 #[test]fn logical_tokens_and_input_immutable(){let a=vec!["/usr/bin/systemd-run".into(),"--property=After=original.guard".into(),"--unit=frame".into(),"/exact/native".into(),"--plan-sha256".into(),"digest".into()];let original=a.clone();let mut r=no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service").unwrap();assert_eq!(r.remove(1),"--no-block");assert_eq!(r,a);assert_eq!(original,a);}
 #[test]fn no_block_wrong_program_rejected(){let a=vec!["/bin/sh".into(),"-c".into()];assert!(no_block_transport(&a,"horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service").is_err());}
 #[test]fn only_exact_metadata_units_allowed(){assert!(allowed_unit("horizon-retained145-terminal-Frame-current1158r2-closedfamily-capability-20261107-v1.service"));assert!(allowed_unit("horizon-postreplay145-current1158r2-fleet-20261107-v1.service"));assert!(!allowed_unit("horizon-postreplay145-current0458-fleet-20261106-v1.service"));assert!(!allowed_unit(GUARD));assert!(!allowed_unit(CONTROLLER));assert!(!allowed_unit("horizon-qualify-185.service"));}
 #[test]fn fresh1058fleet_gets_no_block_transport(){let logical=vec!["/usr/bin/systemd-run".into(),"--unit=fresh1128".into()];let actual=no_block_transport(&logical,"horizon-postreplay145-current1158r2-fleet-20261107-v1.service").unwrap();assert_eq!(actual[1],"--no-block");assert_eq!(&actual[2..],&logical[1..]);}
 #[test]fn exact_old0458fleet_and_frame_targets_reject(){for old in ["horizon-postreplay145-current0458-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current0458-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current0458-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(old));}}
 #[test]fn unresolved_shared_helper_cannot_become_a_fleet_program(){assert!(checked_shared_binding(None).is_err());}
 #[test]fn shared_helper_binding_rejects_unsealed_paths_and_bad_digests(){for pin in [("/bin/sh","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),("/usr/local/lib/jetstreamer/example/jetstreamer-r2","bad")]{assert!(checked_shared_binding(Some(pin)).is_err());}}

 #[test]fn failed0858fleet_namespace_stays_rejected(){assert!(!allowed_unit("horizon-postreplay145-current0858-fleet-20261106-v1.service"));}
 #[test]fn bound_shared_helper_is_exact_qualified_combined_image(){match QUALIFIED_SHARED_HELPER_BINDING {None=>assert!(checked_shared_binding(None).is_err()),Some(pin)=>assert_eq!(checked_shared_binding(Some(pin)).unwrap(),pin)}}

 #[test]fn failed0928fleet_namespace_stays_rejected(){assert!(!allowed_unit("horizon-postreplay145-current0928-fleet-20261106-v1.service"));}

 #[test]fn failed0958fleet_namespace_stays_rejected(){assert!(!allowed_unit("horizon-postreplay145-current0958-fleet-20261106-v1.service"));}

 #[test]fn completed1028_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1028-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1028-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1028-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

 #[test]fn running_original_timer_is_wait_only(){let mut n=timer();n.fields.insert("SubState".into(),"running".into());assert!(timer_wait_only(&n).unwrap());assert!(next_timer(&n,2_000_000).is_err());}
 #[test]fn running_original_timer_cannot_borrow_changed_identity(){for (key,value) in [("Id","foreign.timer"),("InvocationID","00000000000000000000000000000000"),("Unit","foreign.service"),("Job","123")]{let mut n=timer();n.fields.insert("SubState".into(),"running".into());n.fields.insert(key.into(),value.into());assert!(timer_wait_only(&n).is_err(),"{key}");}}
 #[test]fn running_original_timer_still_requires_exact_two_event_policy(){let mut n=timer();n.fields.insert("SubState".into(),"running".into());n.timers[0].1=60_000_000;assert!(timer_wait_only(&n).is_err());n.timers.clear();assert!(timer_wait_only(&n).is_err());}
 #[test]fn unsupported_timer_state_is_not_a_wait_or_launch_window(){for state in ["dead","failed","elapsed","activating"]{let mut n=timer();n.fields.insert("SubState".into(),state.into());assert!(timer_wait_only(&n).is_err());assert!(next_timer(&n,2_000_000).is_err());}}

 #[test]fn completed1058_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1058-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1058-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1058-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

 #[test]fn completed1128_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1128-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1128-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1128-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

 #[test]fn expired1228_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1228-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1228-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1228-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

 #[test]fn completed1258_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1258-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1258-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1258-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

 #[test]fn completed1328_metadata_namespaces_stay_rejected(){for unit in ["horizon-postreplay145-current1328-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1328-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1328-closedfamily-capability-20261106-v2.service","horizon-retained145-terminal-Frame-current1328-closedfamily-capture-20261106-v1.service"]{assert!(!allowed_unit(unit));}}

}

#[cfg(test)] mod rejected_failed1328 { #[test] fn failed_original1328capability_stays_rejected() { assert!(!super::allowed_unit("horizon-retained145-terminal-Frame-current1328-closedfamily-capability-20261106-v1.service")); } }

#[cfg(test)] mod completed1858 { #[test] fn completed1858_names_stay_rejected() { for unit in ["horizon-postreplay145-current1858-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1858-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1858-closedfamily-capture-20261106-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod completed1928 { #[test] fn completed1928_names_stay_rejected() { for unit in ["horizon-postreplay145-current1928-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1928-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1928-closedfamily-capture-20261106-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod completed1958 { #[test] fn completed1958_names_stay_rejected() { for unit in ["horizon-postreplay145-current1958-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current1958-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current1958-closedfamily-capture-20261106-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod completed2028 { #[test] fn completed2028_names_stay_rejected() { for unit in ["horizon-postreplay145-current2028-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current2028-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current2028-closedfamily-capture-20261106-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod data_mode_tests {
 use super::*;
 fn av()->Vec<String>{vec!["/usr/bin/systemd-run","--wait","--pipe","--service-type=exec","--unit=horizon-epoch183-ended-DATA-select-20261105-v1.service",DATA_PROGRAM,"select","/exact/plan.json","--plan-sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","--self-sha256",DATA_SHA,"--output","/current/selection.json"].into_iter().map(str::to_owned).collect()}
 fn terminal()->Native {parse_native(&format!("Id={DATA_UNIT}\nMainPID=0\nControlPID=0\nJob=\nNRestarts=0\nExecMainStatus=0\nResult=success\nActiveState=inactive\nSubState=dead\nInvocationID=\n")).unwrap()}
 #[test]fn explicit_two_modes_only(){assert!(mode_allowed("run-original"));assert!(mode_allowed("run-original-data"));for mode in ["run-data","select","run-original-replay",""]{assert!(!mode_allowed(mode));}}
 #[test]fn data_exact_sync_transport_preserved(){let a=av();checked_data_transport(&a).unwrap();assert!(no_block_transport(&a,DATA_UNIT).is_err());assert!(!allowed_unit(DATA_UNIT));}
 #[test]fn data_cannot_borrow_fleet_or_frame_role(){for role in ["horizon-postreplay145-current1158r2-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current1158r2-closedfamily-capture-20261107-v1.service","horizon-postreplay145-current2028-fleet-20261106-v1.service"]{let mut a=av();a[4]=format!("--unit={role}");assert!(checked_data_transport(&a).is_err());}}
 #[test]fn data_wrong_program_digest_or_operation_rejects(){for (i,bad) in [(5,"/bin/sh"),(6,"capability-check"),(10,"--spec-sha256"),(11,"0000000000000000000000000000000000000000000000000000000000000000")]{let mut a=av();a[i]=bad.into();assert!(checked_data_transport(&a).is_err());}}
 #[test]fn data_no_block_retained_oneshot_collect_or_conflicting_transport_rejects(){for token in ["--no-block","--property=RemainAfterExit=yes","RemainAfterExit=no","--collect","--scope","--service-type=oneshot","--wait"]{let mut a=av();a.insert(1,token.into());assert!(checked_data_transport(&a).is_err(),"{token}");}}
 #[test]fn data_missing_wait_pipe_exec_or_extra_native_tokens_reject(){for i in [1usize,2,3]{let mut a=av();a.remove(i);assert!(checked_data_transport(&a).is_err());}let mut a=av();a.push("extra".into());assert!(checked_data_transport(&a).is_err());}
 #[test]fn data_memory_and_policy_observer_must_both_match_request(){let observer=json!({"path":"/current2058.json","sha256":"a".repeat(64)});let memory=json!({"selection":{"request":{"current":{"observer":observer}}}});let policy=json!({"current":{"observer":observer}});checked_data_lineage(&observer,&memory,&policy).unwrap();for old in ["/prior2028.json","/future2128.json"]{let other=json!({"path":old,"sha256":"b".repeat(64)});assert!(checked_data_lineage(&other,&memory,&policy).is_err());let mut changed=memory.clone();changed["selection"]["request"]["current"]["observer"]=other;assert!(checked_data_lineage(&observer,&changed,&policy).is_err());}}
 #[test]fn data_terminal_allows_cleared_iid_but_no_oneshot_or_live_process(){completed_data(&terminal()).unwrap();for (k,v) in [("MainPID","1"),("ControlPID","1"),("Job","123"),("NRestarts","1"),("ExecMainStatus","1"),("Result","exit-code"),("ActiveState","active"),("SubState","exited")]{let mut n=terminal();n.fields.insert(k.into(),v.into());assert!(completed_data(&n).is_err(),"{k}");}}
}

#[cfg(test)] mod data_property_tests { use super::*; #[test] fn undeclared_prefix_command_or_native_override_rejects(){let base=vec!["/usr/bin/systemd-run","--wait","--pipe","--service-type=exec","--unit=horizon-epoch183-ended-DATA-select-20261105-v1.service",DATA_PROGRAM,"select","/plan","--plan-sha256","a","--self-sha256",DATA_SHA,"--output","/output"].into_iter().map(str::to_owned).collect::<Vec<_>>();for property in ["Type=oneshot","ExecStart=/bin/sh","MemoryMax=128G","User=sol"]{let mut a=base.clone();a.insert(5,property.into());a.insert(5,"-p".into());assert!(checked_data_transport(&a).is_err());}let mut a=base;a.insert(5,"/bin/sh".into());assert!(checked_data_transport(&a).is_err());} }

#[cfg(test)] mod completed2058 { #[test] fn completed2058_names_stay_rejected() { for unit in ["horizon-postreplay145-current2058-fleet-20261106-v1.service","horizon-retained145-terminal-Frame-current2058-closedfamily-capability-20261106-v1.service","horizon-retained145-terminal-Frame-current2058-closedfamily-capture-20261106-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod expired0058 { #[test] fn expired0058_names_stay_rejected() { for unit in ["horizon-postreplay145-current0058-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current0058-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current0058-closedfamily-capture-20261107-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod failed0128 { #[test] fn failed0128_names_stay_rejected() { for unit in ["horizon-postreplay145-current0128-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current0128-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current0128-closedfamily-capture-20261107-v1.service"] { assert!(!super::allowed_unit(unit)); } } }

#[cfg(test)] mod completed0158 { #[test] fn completed0158_names_stay_rejected() { for u in ["horizon-postreplay145-current0158-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current0158-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current0158-closedfamily-capture-20261107-v1.service"] { assert!(!super::allowed_unit(u)); } } }

#[cfg(test)] mod rejected0228 { #[test] fn rejected0228_names_stay_rejected() { for u in ["horizon-postreplay145-current0228-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current0228-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current0228-closedfamily-capture-20261107-v1.service"] { assert!(!super::allowed_unit(u)); } } }

#[cfg(test)] mod successor1058_regressions {
 #[test] fn genuine0728_metadata_cannot_be_reused_as_successor() {for u in ["horizon-postreplay145-current0728-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current0728-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current0728-closedfamily-capture-20261107-v1.service"] {assert!(!super::allowed_unit(u));}}
 #[test] fn unqualified_new_frame_is_closed() {assert!(super::checked_shared_binding(None).is_err());}
 #[test] fn qualified_live145_helper_pin_is_distinct_from_prior0728() {if let Some(pin)=super::QUALIFIED_SHARED_HELPER_BINDING {let p=super::checked_shared_binding(Some(pin)).unwrap();assert_eq!(p.0,"/usr/local/lib/jetstreamer/horizon-live145-fleet-custody-current-helper-tools-20261107-v1/jetstreamer-r2");assert_ne!(p.1,"50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a");}else{assert!(super::checked_shared_binding(None).is_err());}}
}

#[cfg(test)] mod root_qualified_frame_binding_tests {
 #[test] fn unresolved_frame_binding_is_rejected_separately_from_shared_helper() {assert!(super::checked_frame_binding(None).is_err());}
 #[test] fn qualified_frame_image_is_exact_new_normal_seal() {let p=super::checked_frame_binding(super::QUALIFIED_FRAME_BINDING).unwrap();assert_eq!(p.1,"7d4888bf5c5b3559c9d2c49846675ebdd8b09e699d1a681b6d388704e48a0a49");assert!(p.0.ends_with("/jetstreamer-horizon-frame"));}
 #[test] fn frame_binding_rejects_helper_basename_foreign_namespace_and_malformed_digest() {for x in [("/usr/local/lib/jetstreamer/x/jetstreamer-r2","a"),("/tmp/jetstreamer-horizon-frame","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),("/usr/local/lib/jetstreamer/x/jetstreamer-horizon-frame","foreign")] {assert!(super::checked_frame_binding(Some(x)).is_err());}}
}

#[cfg(test)]mod current1158_continuity {#[test]fn original_failed1058_names_can_never_be_retried(){for u in ["horizon-postreplay145-current1058-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current1058-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current1058-closedfamily-capture-20261107-v1.service"] {assert!(!super::allowed_unit(u));}} #[test]fn pending_combined_helper_never_falls_back_to_old50b2(){if let Some(p)=super::QUALIFIED_SHARED_HELPER_BINDING {assert_ne!(p.1,"50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a");}else{assert!(super::checked_shared_binding(None).is_err());}}}

#[cfg(test)] mod rejected_original1158 {#[test] fn original_failed1158_metadata_names_stay_rejected(){for unit in ["horizon-postreplay145-current1158-fleet-20261107-v1.service","horizon-retained145-terminal-Frame-current1158-closedfamily-capability-20261107-v1.service","horizon-retained145-terminal-Frame-current1158-closedfamily-capture-20261107-v1.service"]{assert!(!super::allowed_unit(unit));}}}
