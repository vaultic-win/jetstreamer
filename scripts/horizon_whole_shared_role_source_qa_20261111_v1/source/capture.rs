//! Whole visible host metadata; no unit-name filter, setters, signals or resource credit.
use super::*;
use std::{io::Read,process::{Command,Stdio},thread,time::{Duration,Instant}};
const FIELDS:&str="Id,Names,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Slice,Type,Job,MemoryMax,MemoryHigh,MemoryLow,MemoryMin,MemorySwapMax,MemoryAccounting,TasksMax,Restart,Delegate,KillMode,NoNewPrivileges,ProtectControlGroups,User,Group,ExecStart,ExecMainStartTimestampMonotonic,FragmentPath,SourcePath,DropInPaths,Triggers,TriggeredBy,LimitFSIZE,LimitCORE,UMask,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,ReadOnlyPaths,InaccessiblePaths,RestrictSUIDSGID,RestrictNamespaces,LockPersonality,SystemCallFilter,MemoryDenyWriteExecute";
pub(super) fn unit_name(name:&str)->Result<()> {
 ensure!(!name.starts_with('-')&&name.len()<=255&&name.bytes().all(|b|(33..127).contains(&b))&&["service","scope","slice","timer","socket","path","target","mount","automount","swap","device"].iter().any(|x|name.ends_with(&format!(".{x}"))),"invalid exact unit name");Ok(())
}
pub(super) fn group_name(name:&str)->Result<()> {
 let p=Path::new(name);ensure!(p.is_absolute()&&p.components().all(|c|!matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir))&&!name.contains('\0')&&!name.contains('\n'),"invalid absolute cgroup");Ok(())
}
pub(super) fn contains(parent:&str,child:&str)->bool {Path::new(child).starts_with(parent)}
fn command(args:&[String],cap:usize,deadline:Instant)->Result<String> {
 ensure!(Instant::now()<deadline,"host capture deadline reached");
 let mut child=Command::new("/usr/bin/systemctl").env_clear().env("PATH","/usr/bin:/bin").env("LANG","C.UTF-8").args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
 let out=child.stdout.take().context("native stdout")?;let err=child.stderr.take().context("native stderr")?;
 let read=move |mut f:Box<dyn Read+Send>|->std::io::Result<Vec<u8>>{let mut b=Vec::new();f.by_ref().take(cap as u64+1).read_to_end(&mut b)?;Ok(b)};
 let a=thread::spawn(move||read(Box::new(out)));let b=thread::spawn(move||{let mut f=err;let mut bytes=Vec::new();f.by_ref().take(65537).read_to_end(&mut bytes)?;Ok::<_,std::io::Error>(bytes)});
 let until=deadline.min(Instant::now()+Duration::from_secs(5));let mut timed_out=false;
 let status=loop{match child.try_wait(){Ok(Some(s))=>break Ok(s),Err(e)=>{let _=child.kill();let _=child.wait();break Err(e);},Ok(None)=>{}}
 if Instant::now()>=until {timed_out=true;let _=child.kill();break child.wait();}thread::sleep(Duration::from_millis(5));};
 // Both owned pipe readers are joined even after timeout or a wait error. The only
 // child eligible for kill is this command's own metadata subprocess.
 let stdout=a.join().map_err(|_|anyhow::anyhow!("native stdout reader panicked"));let stderr=b.join().map_err(|_|anyhow::anyhow!("native stderr reader panicked"));
 ensure!(!timed_out,"read-only systemctl exceeded finite deadline");let status=status?;let stdout=stdout??;let stderr=stderr??;
 ensure!(status.success()&&stderr.is_empty()&&stdout.len()<=cap,"native command failed or output exceeded bound");Ok(String::from_utf8(stdout)?)
}
fn cmd(args:&[&str],cap:usize,deadline:Instant)->Result<String>{command(&args.iter().map(|v|(*v).to_owned()).collect::<Vec<_>>(),cap,deadline)}
pub(super) fn kernel_bytes(path:&Path,max:u64)->Result<Vec<u8>>{
 let mut f=OpenOptions::new().read(true).custom_flags(NOFOLLOW|CLOEXEC|0x800).open(path)?;let mut b=Vec::new();f.by_ref().take(max+1).read_to_end(&mut b)?;ensure!(b.len()as u64<=max,"kernel metadata exceeds bound");Ok(b)
}
fn text(path:&Path,max:u64)->Result<String>{Ok(String::from_utf8(kernel_bytes(path,max)?)?)}
fn ids(raw:&str)->Result<Vec<u32>>{let mut s=BTreeSet::new();for item in raw.split_whitespace(){let n=item.parse()?;ensure!(s.insert(n),"duplicate cgroup PID");}Ok(s.into_iter().collect())}
fn loaded(deadline:Instant)->Result<BTreeSet<String>>{
 let raw=cmd(&["list-units","--all","--plain","--no-legend","--no-pager"],16<<20,deadline)?;let mut names=BTreeSet::new();
 for line in raw.lines(){let name=line.split_whitespace().next().context("loaded unit row")?;unit_name(name)?;ensure!(names.insert(name.to_owned()),"duplicate loaded unit");ensure!(names.len()<=32768,"loaded unit bound exceeded");}Ok(names)
}
fn installed(deadline:Instant)->Result<BTreeMap<String,String>>{
 let raw=cmd(&["list-unit-files","--all","--no-legend","--no-pager"],8<<20,deadline)?;let mut out=BTreeMap::new();
 for line in raw.lines(){let mut parts=line.split_whitespace();let name=parts.next().context("installed unit name")?;unit_name(name)?;let state=parts.next().context("installed unit state")?;ensure!(out.insert(name.into(),state.into()).is_none(),"duplicate installed unit");}Ok(out)
}
fn parse_unit_blocks(raw:&str)->Result<Vec<Value>>{
 let mut rows=Vec::new();for block in raw.split("\n\n").filter(|s|!s.trim().is_empty()) {let mut row=serde_json::Map::new();for line in block.lines(){let(k,v)=line.split_once('=').context("native field delimiter")?;ensure!(FIELDS.split(',').any(|x|x==k)&&row.insert(k.into(),json!(v)).is_none(),"unexpected or duplicate native property");}unit_name(row.get("Id").and_then(Value::as_str).context("native Id")?)?;rows.push(json!(row));}Ok(rows)
}
#[cfg(test)]fn parse_units(raw:&str)->Result<BTreeMap<String,Value>>{let mut out=BTreeMap::new();for row in parse_unit_blocks(raw)?{let name=s(&row,"Id")?.to_owned();ensure!(out.insert(name,row).is_none(),"duplicate native unit");}Ok(out)}
fn requested_units(raw:&str,names:&[String])->Result<BTreeMap<String,Value>>{
 let mut canonical=BTreeMap::new();for row in parse_unit_blocks(raw)?{let id=s(&row,"Id")?.to_owned();if let Some(prior)=canonical.insert(id,row.clone()){ensure!(prior==row,"alias snapshots have inconsistent canonical unit metadata");}}
 let mut out=BTreeMap::new();for name in names{let matches=canonical.values().filter(|row|row["Id"]==name.as_str()||row["Names"].as_str().is_some_and(|v|v.split_whitespace().any(|alias|alias==name.as_str()))).collect::<Vec<_>>();ensure!(matches.len()==1,"requested native unit missing or ambiguously aliased");out.insert(name.clone(),(*matches[0]).clone());}
 ensure!(canonical.values().all(|row|out.values().any(|v|v==row)),"unrequested native unit row");Ok(out)
}
fn native_all(names:&BTreeSet<String>,deadline:Instant)->Result<BTreeMap<String,Value>>{
 let names=names.iter().cloned().collect::<Vec<_>>();let mut out=BTreeMap::new();for batch in names.chunks(64){let mut args=vec!["show".to_owned(),"--no-pager".into(),format!("--property={FIELDS}")];args.extend(batch.iter().cloned());let rows=requested_units(&command(&args,8<<20,deadline)?,batch)?;ensure!(rows.len()==batch.len()&&batch.iter().all(|n|rows.contains_key(n)),"native batch cover differs");out.extend(rows);ensure!(serde_json::to_vec(&out)?.len()<=16<<20,"total native metadata bytes exceed funded capture bound");}Ok(out)
}
fn file_stamp(path:&Path)->Result<Value>{let m=fs::symlink_metadata(path)?;ensure!(m.is_file(),"source is not a regular file");Ok(json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"mode":m.mode(),"links":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()}))}
fn source_set(row:&Value,cache:&mut BTreeMap<PathBuf,Value>)->Result<Value>{
 let mut sources=BTreeMap::new();for key in ["FragmentPath","SourcePath","DropInPaths"]{let value=row[key].as_str().unwrap_or("");let paths=if key=="DropInPaths"{value.split_whitespace().collect::<Vec<_>>()}else if value.is_empty(){Vec::new()}else{vec![value]};for path in paths{let canonical=Path::new(path).canonicalize()?;let stamp=file_stamp(&canonical)?;
 let binding=if let Some(cached)=cache.get(&canonical){ensure!(cached["file_identity"]==stamp,"cached unit source changed during capture");cached.clone()}else{let bytes=old(legacy::raw(&canonical))?;ensure!(stamp==file_stamp(&canonical)?,"unit source changed while hashing");let value=json!({"canonical_path":canonical,"sha256":sha(&bytes),"bytes":bytes.len(),"file_identity":stamp});cache.insert(canonical,value.clone());value};sources.insert(path.to_owned(),binding);}}Ok(json!(sources))
}
fn pids()->Result<BTreeSet<u32>>{let mut p=BTreeSet::new();for e in fs::read_dir("/proc")?{let e=e?;if let Some(n)=e.file_name().to_str().and_then(|v|v.parse::<u32>().ok()){ensure!(p.insert(n),"duplicate proc PID");ensure!(p.len()<=65536,"PID census bound exceeded");}}Ok(p)}
fn stat(raw:&str)->Result<(char,u32,u64,u64)>{let(_,tail)=raw.rsplit_once(')').context("proc stat command")?;let f=tail.split_whitespace().collect::<Vec<_>>();ensure!(f.len()>=20,"short proc stat");Ok((f[0].chars().next().context("proc state")?,f[1].parse()?,f[6].parse()?,f[19].parse()?))}
fn same_stat_identity(a:(char,u32,u64,u64),b:(char,u32,u64,u64))->bool{(a.1,a.2,a.3)==(b.1,b.2,b.3)}
fn mapped_image(base:&Path)->Result<Value>{let path=fs::read_link(base.join("exe"))?;let disk=fs::metadata(&path)?;let mapped=fs::metadata(base.join("exe"))?;ensure!(disk.dev()==mapped.dev()&&disk.ino()==mapped.ino(),"process mapped executable differs from filesystem");Ok(json!({"path":path,"device":mapped.dev(),"inode":mapped.ino(),"bytes":mapped.len()}))}
pub(super) fn proc_row(pid:u32)->Result<Value>{
 let base=PathBuf::from(format!("/proc/{pid}"));let first=stat(&text(&base.join("stat"),65536)?)?;let group=text(&base.join("cgroup"),65536)?;let group=group.strip_prefix("0::").and_then(|s|s.strip_suffix('\n')).context("one unified process cgroup required")?;group_name(group)?;
 let cmd=kernel_bytes(&base.join("cmdline"),1<<20)?;let argv=if cmd.is_empty(){Vec::new()}else{ensure!(cmd.last()==Some(&0),"unterminated cmdline");cmd[..cmd.len()-1].split(|b|*b==0).map(|v|String::from_utf8(v.to_vec())).collect::<std::result::Result<Vec<_>,_>>()?};
 let kernel_thread=first.2&0x0020_0000!=0;let image=if kernel_thread{ensure!(argv.is_empty(),"kernel thread has userspace argv");Value::Null}else{mapped_image(&base)?};
 let last=stat(&text(&base.join("stat"),65536)?)?;
 ensure!(same_stat_identity(first,last)&&text(&base.join("cgroup"),65536)?==format!("0::{group}\n")&&kernel_bytes(&base.join("cmdline"),1<<20)?==cmd,"process birth/parent/flags/argv/cgroup changed during census");
 if !kernel_thread{ensure!(image==mapped_image(&base)?,"process executable changed during census");}
 Ok(json!({"pid":pid,"parent_pid":first.1,"start_ticks":first.3,"flags":first.2,"state":first.0.to_string(),"state_after":last.0.to_string(),"kernel_thread":kernel_thread,"image":image,"argv":argv,"cgroup":group}))
}
pub(super) fn stable_process_identity(process:&Value)->Result<Value>{
 let mut out=serde_json::Map::new();for key in["pid","parent_pid","start_ticks","flags","kernel_thread","image","argv","cgroup"]{let value=process.get(key).context("stable process identity field missing")?;out.insert(key.into(),value.clone());}Ok(json!(out))
}
fn cgroups(deadline:Instant,issues:&mut Vec<Value>)->Result<BTreeMap<String,Value>>{
 let root=Path::new("/sys/fs/cgroup");ensure!(root.canonicalize()?==root,"noncanonical cgroup root");let mut pending=vec![root.to_path_buf()];let mut rows=BTreeMap::new();let mut row_bytes=0usize;
 while let Some(path)=pending.pop(){if Instant::now()>=deadline||rows.len()>=65536{issues.push(json!({"kind":"incomplete_cgroup_hierarchy","reason":"cgroup census deadline/count bound","remaining_paths":pending.len()+1}));break;}
 let group=format!("/{}",path.strip_prefix(root)?.display());
 if path.canonicalize().ok().as_deref()!=Some(path.as_path()){issues.push(json!({"kind":"unresolved_cgroup_directory","cgroup":group,"reason":"cgroup path vanished or became noncanonical"}));rows.insert(group,json!({"unresolved":true}));continue;}
 let scan=(||->Result<()>{for e in fs::read_dir(&path)?{let e=e?;if e.file_type()?.is_dir(){ensure!(pending.len()+rows.len()<65536,"cgroup pending/count bound");pending.push(e.path());}}Ok(())})();
 if let Err(e)=scan{issues.push(json!({"kind":"unresolved_cgroup_directory","cgroup":group,"reason":e.to_string()}));}
 let mut row=serde_json::Map::new();let mut unavailable=Vec::new();
 for key in["memory.max","memory.high","memory.low","memory.min","memory.swap.max","pids.max","cgroup.procs","cgroup.events","cgroup.controllers","cgroup.subtree_control"]{
 let value=(||->Result<Value>{let raw=text(&path.join(key),1<<20)?;if key=="cgroup.procs"{Ok(json!(ids(&raw)?))}else{Ok(json!(raw.trim()))}})();
 match value{Ok(v)=>{row.insert(key.into(),v);},Err(e)=>{row.insert(key.into(),Value::Null);unavailable.push(key);if path!=root||key=="cgroup.procs"{issues.push(json!({"kind":"unavailable_cgroup_control","cgroup":group,"control":key,"reason":e.to_string()}));}}}}
 row.insert("unavailable_controls".into(),json!(unavailable));row_bytes=row_bytes.checked_add(serde_json::to_vec(&row)?.len()+group.len()+32).context("cgroup metadata overflow")?;ensure!(row_bytes<=4<<20,"total cgroup metadata exceeds funded capture bound");rows.insert(group,json!(row));}Ok(rows)
}
pub(super) fn endpoint(required:&BTreeSet<String>,deadline:Instant)->Result<Value>{
 let names=loaded(deadline)?;let files=installed(deadline)?;let mut capture_names=names.clone();capture_names.extend(required.iter().cloned());capture_names.extend(files.iter().filter(|(_,state)|!matches!(state.as_str(),"masked"|"masked-runtime")).map(|(name,_)|name.clone()));ensure!(capture_names.len()<=32768,"combined current/future unit count bound");let mut issues=Vec::new();let units=match native_all(&capture_names,deadline){Ok(v)=>v,Err(e)=>{issues.push(json!({"kind":"incomplete-native-unit-census","requested_units":capture_names,"reason":e.to_string()}));BTreeMap::new()}};let mut source_rows=BTreeMap::new();let mut source_cache=BTreeMap::new();let mut source_bytes=0usize;
 for(name,row)in &units{ensure!(Instant::now()<deadline,"source census deadline");match source_set(row,&mut source_cache){Ok(v)=>{source_bytes=source_bytes.checked_add(serde_json::to_vec(&v)?.len()+name.len()+32).context("source metadata overflow")?;ensure!(source_bytes<=8<<20,"source metadata exceeds funded capture bound");source_rows.insert(name.clone(),v);},Err(e)=>issues.push(json!({"kind":"unit_source_unreadable","unit":name,"reason":e.to_string()}))}}
 let before_pids=pids()?;let mut processes=BTreeMap::new();let mut process_bytes=0usize;for pid in &before_pids{ensure!(Instant::now()<deadline,"process census deadline");match proc_row(*pid){Ok(v)=>{process_bytes=process_bytes.checked_add(serde_json::to_vec(&v)?.len()+32).context("process metadata bytes overflow")?;ensure!(process_bytes<=4<<20,"total process metadata exceeds funded capture bound");processes.insert(pid.to_string(),v);},Err(e)=>issues.push(json!({"kind":"unresolved_process","pid":pid,"reason":e.to_string()}))}}
 let groups=cgroups(deadline,&mut issues)?;let after_pids=pids()?;if before_pids!=after_pids{issues.push(json!({"kind":"PID_membership_changed","before":before_pids,"after":after_pids}));}let after_names=loaded(deadline)?;if names!=after_names{issues.push(json!({"kind":"loaded_unit_membership_changed","before":names,"after":after_names}));}
 let after_files=installed(deadline)?;if files!=after_files{issues.push(json!({"kind":"installed_launch_routes_changed","before":files,"after":after_files}));}
 for(path,v)in &source_cache{match file_stamp(path){Ok(stamp)if stamp==v["file_identity"]=>{},other=>issues.push(json!({"kind":"unit_source_changed_after_hash","path":path,"reason":format!("{other:?}")}))}}
 for(name,bindings)in &source_rows{for(path,binding)in bindings.as_object().context("captured source object")?{if Path::new(path).canonicalize().ok().as_deref()!=binding["canonical_path"].as_str().map(Path::new){issues.push(json!({"kind":"unit_source_route_changed","unit":name,"path":path}));}}}
 let boot=text(Path::new("/proc/sys/kernel/random/boot_id"),128)?;let release=text(Path::new("/proc/sys/kernel/osrelease"),256)?;let meminfo=text(Path::new("/proc/meminfo"),65536)?;
 Ok(json!({"boot_id":boot.trim(),"kernel_release":release.trim(),"units":units,"installed_unit_files":files,"unit_sources":source_rows,"processes":processes,"cgroups":groups,"kernel_meminfo":meminfo,"capture_issues":issues,"collection_scope":{"processes":"all visible numeric /proc entries","cgroups":"entire visible unified hierarchy","systemd":"system manager loaded units and unmasked installed unit files","user_manager_or_non_systemd_future_launch_routes_qualified_by_capture":false},"recorded_unix_seconds":now()?}))
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn all_unit_kinds_including_non_horizon_session_are_admitted(){for n in["ssh.service","session-42.scope","user-1001.slice","dbus.socket"]{unit_name(n).unwrap();}assert!(unit_name("--help").is_err());}
 #[test]fn ancestry_uses_path_components_not_string_prefix(){assert!(contains("/slice/a.service","/slice/a.service/worker"));assert!(!contains("/slice/a.service","/slice/a.service-foreign"));}
 #[test]fn repeated_native_rows_or_properties_reject(){assert!(parse_units("Id=x.service\nId=x.service\n").is_err());assert!(parse_units("Id=x.service\n\nId=x.service\n").is_err());}
 #[test]fn installed_alias_route_requires_exact_canonical_metadata(){let raw="Id=ssh.service\nNames=ssh.service sshd.service\n\nId=ssh.service\nNames=ssh.service sshd.service\n";let names=vec!["ssh.service".into(),"sshd.service".into()];assert_eq!(requested_units(raw,&names).unwrap().len(),2);assert!(requested_units(raw,&["other.service".into()]).is_err());assert!(requested_units("Id=ssh.service\nNames=ssh.service sshd.service\n\nId=ssh.service\nNames=ssh.service\n",&names).is_err());}
 #[test]fn stat_birth_and_kernel_thread_bit_are_exact(){let mut fields=vec!["0";20];fields[0]="S";fields[6]="2097152";fields[19]="123";let v=stat(&format!("2 (kthreadd) {}",fields.join(" "))).unwrap();assert_eq!(v.3,123);assert_ne!(v.2&0x0020_0000,0);}
 #[test]fn state_change_preserves_identity_but_birth_parent_or_flags_change_rejects(){let a=('S',1,2097152,123);assert!(same_stat_identity(a,('R',1,2097152,123)));assert!(!same_stat_identity(a,('S',2,2097152,123)));assert!(!same_stat_identity(a,('S',1,0,123)));assert!(!same_stat_identity(a,('S',1,2097152,124)));}
 #[test]fn endpoint_identity_ignores_only_volatile_state(){let mut a=json!({"pid":7,"parent_pid":1,"start_ticks":11,"flags":0,"kernel_thread":false,"image":{"inode":9},"argv":["worker"],"cgroup":"/x.service","state":"S","state_after":"R"});let b=stable_process_identity(&a).unwrap();a["state"]=json!("R");assert_eq!(stable_process_identity(&a).unwrap(),b);a["argv"]=json!(["worker","changed"]);assert_ne!(stable_process_identity(&a).unwrap(),b);}
}
