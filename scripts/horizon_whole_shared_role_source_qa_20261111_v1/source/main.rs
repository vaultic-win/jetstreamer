#![recursion_limit = "512"]
//! Report-only whole-host role census. No selector, admission or resource setter.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs::{self, OpenOptions}, io::Read,
 os::unix::fs::{MetadataExt, OpenOptionsExt}, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
#[allow(dead_code)] mod legacy;
#[allow(dead_code)] #[path = "memory_main.rs"] mod current_memory;
mod capture;
mod budget;
const NOFOLLOW:i32=0x20000;
const CLOEXEC:i32=0x80000;
const PLAN:&str=include_str!("SEALED_PLAN.json");
const IMAGE:&str="/usr/local/lib/jetstreamer/horizon-whole-shared-role-census-tools-20261111-v1/check";
const SOURCE_ROOT:&str="/usr/local/lib/jetstreamer/horizon-whole-shared-role-census-source-20261111-v2";
const OWN:&str="horizon-whole-shared-role-census-qualification-20261111-v1.service";
const PRIMARY:&str="01a1af2a-9ce8-76a2-8939-b2112bd38f53";
fn old<T>(r:legacy::R<T>)->Result<T>{r.map_err(|e|anyhow::anyhow!(e.to_string()))}
fn s<'a>(v:&'a Value,k:&str)->Result<&'a str>{v[k].as_str().with_context(||format!("missing string {k}"))}
fn n(v:&Value,k:&str)->Result<u64>{v[k].as_u64().with_context(||format!("missing integer {k}"))}
fn sha(raw:&[u8])->String{format!("{:x}",Sha256::digest(raw))}
fn now()->Result<u64>{Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())}
fn exact_keys(v:&Value,keys:&[&str])->Result<()>{let actual=v.as_object().context("typed object")?;ensure!(actual.len()==keys.len()&&keys.iter().all(|k|actual.contains_key(*k)),"unknown/missing typed field");Ok(())}
fn bound(b:&Value)->Result<Value>{old(legacy::bound(b))}
fn identity(m:&fs::Metadata)->(u64,u64,u64,i64,i64,i64,i64,u32,u32,u64){(m.dev(),m.ino(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec(),m.uid(),m.mode(),m.nlink())}
fn file_identity(binding:&Value)->Result<Value>{
 let path=Path::new(s(binding,"path")?);ensure!(path.is_absolute()&&path.canonicalize()?==path,"canonical source/image path required");
 let mut f=OpenOptions::new().read(true).custom_flags(NOFOLLOW|CLOEXEC).open(path)?;let before=f.metadata()?;
 ensure!(before.is_file()&&before.uid()==0&&before.nlink()==1&&before.mode()&0o022==0&&before.len()<=512<<20,"unsafe or unbounded source/image");
 let mut hash=Sha256::new();let mut buf=[0u8;65536];let mut count=0u64;loop{let got=f.read(&mut buf)?;if got==0{break;}count=count.checked_add(got as u64).context("source length overflow")?;ensure!(count<=before.len(),"source grew");hash.update(&buf[..got]);}
 ensure!(count==before.len()&&identity(&before)==identity(&f.metadata()?)&&identity(&before)==identity(&fs::symlink_metadata(path)?),"source/image changed during streaming hash");
 ensure!(format!("{:x}",hash.finalize())==s(binding,"sha256")?,"source/image digest mismatch");
 Ok(json!({"path":path,"device":before.dev(),"inode":before.ino(),"bytes":before.len(),"sha256":binding["sha256"],"mtime":before.mtime(),"mtime_nsec":before.mtime_nsec(),"ctime":before.ctime(),"ctime_nsec":before.ctime_nsec()}))
}
fn authenticate_file(b:&Value)->Result<()>{file_identity(b).map(|_|())}
fn plan_contract(p:&Value)->Result<()>{
 ensure!(p["schema"]=="horizon-whole-shared-role-census-plan-v1"&&p["owner"]=="/root"&&p["primary_thread"]==PRIMARY&&p["own_unit"]==OWN&&p["image_path"]==IMAGE,"exclusive source-pinned report plan required");
 for key in ["resource_promise_ending_authorized","replay_launch_authorized","native_Frame_or_full_Reader_authority","future_host_or_shared_role_bound_claimed"]{ensure!(p[key]==false,"report must not grant {key}");}
 ensure!(n(p,"retained_shared_bytes")?==64u64<<30&&n(p,"historical_host_bytes")?==43_603_734_528&&n(p,"separate_input_bytes")?==2_684_354_560,"retained pool and historical host/input split differ");
 ensure!(p["historical_kernel_fulfillment_reused"]==false&&p["global_future_kernel_reserve_disjoint_from_historical_host"]==true,"same kernel minima cannot be charged/credited twice");
 ensure!((1..=30).contains(&n(p,"maximum_capture_seconds")?),"fresh finite capture deadline must be at most30seconds");
 ensure!(p["template_requires_root_binding"]==false,"unbound source template: Root must bind fresh actual plan and rebuild/seal");Ok(())
}
fn native_accounting(v:&Value)->Result<()>{
 ensure!(v["schema"]=="horizon-whole-role-native16-actual-booking-v1"&&v["retained_native16_bytes"]==16u64<<30&&v["existing_commitments_bytes"]==13_757_317_120u64&&v["native_callback_bytes"]==512u64<<20&&v["separate_root_outer_bytes"]==1u64<<30&&v["compiler_concurrent"]==false&&v["all_original_promises_retained"]==true,"actual native512 callback and separate Root outer booking required");
 ensure!(n(v,"existing_commitments_bytes")?.checked_add(n(v,"native_callback_bytes")?).and_then(|b|b.checked_add(n(v,"separate_root_outer_bytes").ok()?)).is_some_and(|sum|sum<=16u64<<30),"native16 including distinct Root outer exceeded");
 let evidence=v["actual_ledger_evidence"].as_array().context("actual native ledger evidence")?;ensure!(!evidence.is_empty(),"empty native ledger evidence");for b in evidence{bound(b)?;}Ok(())
}
fn lock_record(raw:&str,dev:u64,ino:u64,pid:u32)->bool{
 let major=((dev>>8)&0xfff)|((dev>>32)&0xfffff000);let minor=(dev&0xff)|((dev>>12)&0xffffff00);
 raw.lines().any(|line|{let f=line.split_whitespace().collect::<Vec<_>>();if f.len()!=8||f[1]!="FLOCK"||f[2]!="ADVISORY"||f[3]!="WRITE"||f[4].parse::<u32>().ok()!=Some(pid)||f[6]!="0"||f[7]!="EOF"{return false;}let a=f[5].split(':').collect::<Vec<_>>();a.len()==3&&u64::from_str_radix(a[0],16).ok()==Some(major)&&u64::from_str_radix(a[1],16).ok()==Some(minor)&&a[2].parse::<u64>().ok()==Some(ino)})
}
fn native_lock(v:&Value)->Result<Value>{
 let path=Path::new(s(v,"lock_path")?);ensure!(path.is_absolute()&&path.canonicalize()?==path,"exact native16 lock path required");let m=fs::symlink_metadata(path)?;ensure!(m.is_file()&&m.uid()==0&&m.nlink()==1&&m.mode()&0o022==0,"unsafe native16 lock");
 ensure!(fs::read_link("/proc/self/fd/9")?==path,"actual inherited native16 FD9 required");let fd=fs::metadata("/proc/self/fd/9")?;ensure!(m.dev()==fd.dev()&&m.ino()==fd.ino(),"native lock FD9 inode differs");
 let pid=u32::try_from(n(v,"lock_holder_pid")?)?;let holder=capture::proc_row(pid)?;ensure!(holder["start_ticks"]==v["lock_holder_start_ticks"]&&holder["cgroup"]==v["lock_holder_cgroup"],"native lock holder changed");
 let locks=String::from_utf8(capture::kernel_bytes(Path::new("/proc/locks"),1<<20)?)?;ensure!(lock_record(&locks,m.dev(),m.ino(),pid),"no exact held exclusive native16 lock; no lock is acquired by this report");let fdinfo=String::from_utf8(capture::kernel_bytes(Path::new("/proc/self/fdinfo/9"),65536)?)?;ensure!(fdinfo.lines().filter_map(|line|line.strip_prefix("lock:")).any(|line|lock_record(line.trim(),m.dev(),m.ino(),pid)),"FD9 description does not carry the exact exclusive native16 FLOCK");Ok(json!({"device":m.dev(),"inode":m.ino(),"holder":capture::stable_process_identity(&holder)?,"exclusive_write_record_observed":true}))
}
fn own_identity(p:&Value)->Result<Value>{
 let mine=old(legacy::native(OWN))?;ensure!(mine["InvocationID"]==std::env::var("INVOCATION_ID")?&&s(&mine,"MainPID")?.parse::<u32>()?==std::process::id()&&mine["ActiveState"]=="active"&&mine["SubState"]=="running"&&mine["MemoryMax"]=="536870912"&&mine["MemorySwapMax"]=="0"&&mine["Restart"]=="no"&&mine["NRestarts"]=="0"&&mine["Delegate"]=="no"&&mine["KillMode"]=="control-group","exact native512 own identity required");
 let group=String::from_utf8(capture::kernel_bytes(Path::new("/proc/self/cgroup"),65536)?)?;ensure!(group.trim()==format!("0::/system.slice/{OWN}")&&p["own_cgroup"]==format!("/system.slice/{OWN}"),"own invocation cgroup differs");Ok(mine)
}
fn protected(fleet:&Value,p:&Value)->Result<BTreeMap<String,Value>>{
 let mut expected=BTreeMap::<String,Value>::new();for r in fleet["actual_executing_replays"].as_array().context("seven actual local2 replays")?{let u=&r["unit"];ensure!(expected.insert(s(u,"Id")?.into(),json!({"unit":u["Id"],"invocation_id":u["InvocationID"],"main_pid":u["MainPID"]})).is_none(),"duplicate replay owner");}
 let back=p["protected_background_owners"].as_array().context("protected background owners")?;old(legacy::complete_background_census(back))?;
 for r in back{ensure!(expected.insert(s(r,"unit")?.into(),r.clone()).is_none(),"overlapping protected owner");}
 let mut result=BTreeMap::new();for(name,want)in expected{let actual=old(legacy::native(&name))?;old(legacy::owner_matches(&actual,&want))?;result.insert(name,actual);}Ok(result)
}
fn endpoint_changes(a:&Value,b:&Value)->Vec<Value>{
 let mut issues=Vec::new();for key in["boot_id","kernel_release","units","installed_unit_files","unit_sources"]{if a[key]!=b[key]{issues.push(json!({"gate":"endpoint-identity-source-limit-or-launch-change","field":key}));}}
 if let(Some(x),Some(y))=(a["processes"].as_object(),b["processes"].as_object()) {if x.keys().collect::<Vec<_>>()!=y.keys().collect::<Vec<_>>(){issues.push(json!({"gate":"PID-membership-changed-between-endpoints"}));}for(pid,row)in x{let Some(other)=y.get(pid)else{issues.push(json!({"gate":"process-disappeared-between-endpoints","pid":pid}));continue;};let check=(||->Result<()>{ensure!(capture::stable_process_identity(row)?==capture::stable_process_identity(other)?,"process birth/parent/flags/image/argv/cgroup changed");Ok(())})();if let Err(e)=check{issues.push(json!({"gate":"process-identity-argv-image-or-cgroup-changed","pid":pid,"reason":e.to_string()}));}}}
 if let(Some(x),Some(y))=(a["cgroups"].as_object(),b["cgroups"].as_object()){if x.keys().collect::<Vec<_>>()!=y.keys().collect::<Vec<_>>(){issues.push(json!({"gate":"cgroup-hierarchy-changed"}));}for(group,row)in x{let Some(other)=y.get(group)else{issues.push(json!({"gate":"cgroup-disappeared-between-endpoints","cgroup":group}));continue;};for key in["memory.max","memory.high","memory.low","memory.min","memory.swap.max","pids.max","cgroup.procs","cgroup.controllers","cgroup.subtree_control"]{if row[key]!=other[key]{issues.push(json!({"gate":"cgroup-membership-limit-or-controller-changed","cgroup":group,"field":key}));}}}}issues
}
fn own_ancestor_controls(p:&Value,e:&Value)->Result<()>{
 let required=p["own_expected_ancestor_controls"].as_object().context("source-pinned own ancestor controls")?;let mut group=Path::new(s(p,"own_cgroup")?);let mut seen=BTreeSet::new();loop{let name=group.to_str().context("own ancestor UTF8")?;seen.insert(name.to_owned());let row=required.get(name).context("omitted own ancestor control")?;let actual=&e["cgroups"][name];ensure!(!actual.is_null(),"own ancestor absent");for key in["memory.max","memory.high","memory.low","memory.min","memory.swap.max","pids.max","cgroup.controllers","cgroup.subtree_control"]{ensure!(actual[key]==row[key],"own ancestor control differs: {name}:{key}");}
 if name=="/"{break;}group=group.parent().context("own ancestor root")?;}ensure!(seen==required.keys().cloned().collect(),"unexpected own ancestor claims");
 let own=&e["units"][OWN];let profile=&p["own_expected_native_controls"];ensure!(profile.as_object().is_some_and(|x|!x.is_empty()),"exact own native protections required");for key in["MemoryMax","MemoryHigh","MemoryMin","MemoryLow","MemorySwapMax","TasksMax","Delegate","KillMode","NoNewPrivileges","ProtectControlGroups","User","Group","Restart","LimitFSIZE","LimitCORE","UMask","ProtectSystem","ProtectHome","PrivateNetwork","PrivateTmp","CapabilityBoundingSet","AmbientCapabilities","ReadWritePaths","ReadOnlyPaths","InaccessiblePaths","RestrictSUIDSGID","RestrictNamespaces","LockPersonality","SystemCallFilter","MemoryDenyWriteExecute"]{ensure!(own[key].is_string()&&own[key]==profile[key],"own native protection differs: {key}");}Ok(())
}
fn record(r:Result<Value>,gate:&str,issues:&mut Vec<Value>)->Value{match r{Ok(v)=>v,Err(e)=>{issues.push(json!({"gate":gate,"reason":format!("{e:#}")}));Value::Null}}}
fn execute(p:&Value,own_image:&Value)->Result<Value>{
 plan_contract(p)?;let context=current_memory::report_context(p)?;let own_before=own_identity(p)?;let own_process_before=capture::proc_row(std::process::id())?;let booking=bound(&p["native_booking"])?;native_accounting(&booking)?;let lock_before=native_lock(&booking)?;let protected_before=protected(&context["fleet"],p)?;
 let verifiers=p["retained_verification_roles"].as_array().context("retained verifier slots")?;let retained=old(legacy::retained_caps(verifiers))?;let verifier_before=old(legacy::verification_native(verifiers))?;
 let roles=budget::roles(&p["roles"])?;let mut issues=budget::future_arithmetic(&roles,n(p,"historical_host_bytes")?,n(p,"separate_input_bytes")?);issues.extend(budget::required_roles(&roles,p));issues.push(json!({"gate":"complete-user-manager-and-non-systemd-future-launch-policy-unqualified","reason":"system-manager routes and all visible processes/cgroups are captured; exact installed user-manager, cron, login/SSH/session and arbitrary future external launch grammar are not qualified by this source. No complete future shared bound can pass."}));issues.extend(budget::validate_funding(&roles));let (images,image_issues)=budget::authenticated_images(&roles,own_image);issues.extend(image_issues);let guard_before=current_memory::guard_context(p,&context["fleet"])?;issues.extend(budget::required_guards(&roles,&guard_before));
 let mut required=roles.iter().flat_map(|r|r.units.iter().cloned()).collect::<BTreeSet<_>>();required.insert(OWN.into());let deadline=std::time::Instant::now()+std::time::Duration::from_secs(n(p,"maximum_capture_seconds")?);
 let before=record(capture::endpoint(&required,deadline),"whole-host-endpoint-before",&mut issues);let current_before=budget::evaluate(&before,&roles,&images);let after=record(capture::endpoint(&required,deadline),"whole-host-endpoint-after",&mut issues);let current_after=budget::evaluate(&after,&roles,&images);issues.extend(endpoint_changes(&before,&after));
 for e in [&before,&after]{let identity= capture::stable_process_identity(&e["processes"][std::process::id().to_string()]);if identity.ok()!=Some(capture::stable_process_identity(&own_process_before)?){issues.push(json!({"gate":"own-process-birth-or-image-changed"}));}
 if let Err(error)=own_ancestor_controls(p,e){issues.push(json!({"gate":"own-native-or-ancestor-controls","reason":error.to_string()}));}
 if let Some(rows)=e["capture_issues"].as_array(){issues.extend(rows.iter().cloned());}}
 for e in [&current_before,&current_after]{issues.extend(e["issues"].as_array().context("role issues")?.iter().cloned());}
 let final_context=record(current_memory::report_context(p),"final-current-authority-fleet-semantics",&mut issues);if context!=final_context{issues.push(json!({"gate":"current-authority-fleet-semantics-changed"}));}
 let guard_after=record(current_memory::guard_context(p,&context["fleet"]),"final-current-guard-protection",&mut issues);
 let final_protected=record(protected(&context["fleet"],p).map(|v|json!(v)),"final-protected-owners",&mut issues);if final_protected!=json!(protected_before){issues.push(json!({"gate":"protected-owner-or-cap-changed"}));}
 let final_own=record(own_identity(p),"final-own-native",&mut issues);if final_own!=own_before{issues.push(json!({"gate":"own-native-identity-changed"}));}
 let lock_after=record(native_lock(&booking),"final-native16-lock",&mut issues);if lock_before!=lock_after{issues.push(json!({"gate":"native16-lock-custody-changed"}));}
 let verifier_after=record(old(legacy::verification_native(verifiers)),"final-retained-verifier",&mut issues);if verifier_before!=verifier_after{issues.push(json!({"gate":"retained-verifier-identity-cap-source-changed"}));}
 for (path,image)in &images{let check=(||->Result<()>{let m=fs::symlink_metadata(path)?;for (key,value)in[("device",json!(m.dev())),("inode",json!(m.ino())),("bytes",json!(m.len())),("mtime",json!(m.mtime())),("mtime_nsec",json!(m.mtime_nsec())),("ctime",json!(m.ctime())),("ctime_nsec",json!(m.ctime_nsec()))]{ensure!(image[key]==value,"authenticated executable changed: {path}:{key}");}Ok(())})();if let Err(e)=check{issues.push(json!({"gate":"authenticated-image-changed-after-capture","reason":e.to_string()}));}}
 let mut report=json!({"schema":"horizon-whole-shared-role-census-report-v1","owner":"/root","primary_thread":PRIMARY,"plan_sha256":sha(PLAN.as_bytes()),"recorded_unix_seconds":now()?,"current_positive_evidence":{"context":context,"protected_owners":protected_before,"guards_before":guard_before,"guards_after":guard_after,"final_context":final_context,"final_protected_owners":final_protected,"final_own":final_own,"authenticated_images":images,"verifier_before":verifier_before,"verifier_after":verifier_after,"all96GiB_actual_and_future_verifier_caps_retained_bytes":retained,"native_booking":booking,"native_lock_before":lock_before,"native_lock_after":lock_after,"own":own_before,"own_process":own_process_before},"current_before":current_before,"current_after":current_after,"failed_gates":issues,"candidate_current_and_future_checks_complete":issues.is_empty(),"future_bound_accepted":false,"retained_shared_bytes":64u64<<30,"new_memory_credit_bytes":0,"new_physical_or_DATA_credit_bytes":0,"shared_budget_ending_authorized":false,"new_replay_admission_authorized":false,"producer_or_guard_mutations":false,"remote_mutations":false,"next_gate":"Root must qualify complete actual current/future bounds and production liveness. A distinct once-only selector and genuine downstream consumer/admission transition are required; this report selects no budget."});
 let fields=report.as_object_mut().context("report fields")?;fields.insert("endpoint_before".into(),before);fields.insert("endpoint_after".into(),after);Ok(report)
}
fn compiled_source_closure()->BTreeMap<String,String>{
 let mut rows=BTreeMap::new();macro_rules! pin{($path:literal)=>{rows.insert($path.into(),sha(include_bytes!($path)));};}
 pin!("main.rs");pin!("capture.rs");pin!("budget.rs");pin!("legacy.rs");pin!("main_tests.rs");pin!("budget_tests.rs");
 pin!("memory_main.rs");pin!("data_guard_reader.rs");pin!("interrupted_recovery.rs");pin!("local2_owners.rs");pin!("local2_owners_tests.rs");pin!("local2-owners.json");pin!("data-guard-registrations.json");pin!("SEALED_PLAN.json");pin!("BUILD_GRAPH_AND_RECIPE.json");rows
}
fn source_closure(manifest:&Value)->Result<()>{
 let expected=compiled_source_closure();let files=manifest["files"].as_array().context("complete source closure")?;ensure!(files.len()==expected.len(),"source closure cardinality differs");let mut seen=BTreeSet::new();
 for b in files{let p=Path::new(s(b,"path")?);let relative=p.strip_prefix(SOURCE_ROOT)?.to_str().context("source relative path UTF8")?;ensure!(seen.insert(relative.to_owned())&&expected.get(relative).is_some_and(|digest|b["sha256"]==digest.as_str()),"omitted/duplicate/changed compiled source or build recipe");authenticate_file(b)?;}Ok(())
}
fn main()->Result<()>{
 let args=std::env::args().collect::<Vec<_>>();ensure!(args.len()==5&&args[1]=="--sealed-plan"&&args[3]=="--artifact","sealed plan and genuine Root artifact required");let bytes=old(legacy::raw(Path::new(&args[2])))?;ensure!(bytes==PLAN.as_bytes(),"plan differs from exact compile-time bytes");let plan:Value=serde_json::from_slice(&bytes)?;
 let artifact=bound(&json!({"path":args[4],"sha256":sha(&old(legacy::raw(Path::new(&args[4])))?)}))?;
 ensure!(artifact["schema"]=="horizon-whole-shared-role-native-artifact-v1"&&artifact["owner"]=="/root"&&artifact["primary_thread"]==PRIMARY&&artifact["plan_sha256"]==sha(PLAN.as_bytes())&&artifact["four_strict_configurations_passed"]==true&&artifact["all_retained_and_new_tests_passed"]==true&&artifact["source_normally_sealed"]==true&&artifact["image_normally_sealed"]==true,"genuine qualified normal-seal artifact required");
 ensure!(fs::read_link("/proc/self/exe")?==Path::new(IMAGE)&&artifact["image"]["path"]==IMAGE,"exact selected report image required");let own_image=file_identity(&artifact["image"])?;let source=bound(&artifact["source_manifest"])?;ensure!(source["schema"]=="horizon-whole-shared-role-source-manifest-v1"&&source["plan_sha256"]==sha(PLAN.as_bytes()),"exact normally sealed source manifest required");
 source_closure(&source)?;
 let report=match execute(&plan,&own_image){Ok(v)=>v,Err(e)=>json!({"schema":"horizon-whole-shared-role-census-report-v1","owner":"/root","primary_thread":PRIMARY,"plan_sha256":sha(PLAN.as_bytes()),"recorded_unix_seconds":now()?,"failed_gates":[{"gate":"required-authentication-or-finite-capture-failed","reason":format!("{e:#}")}],"current_positive_evidence":null,"candidate_current_and_future_checks_complete":false,"future_bound_accepted":false,"retained_shared_bytes":64u64<<30,"new_memory_credit_bytes":0,"new_physical_or_DATA_credit_bytes":0,"shared_budget_ending_authorized":false,"new_replay_admission_authorized":false,"producer_or_guard_mutations":false,"remote_mutations":false})};
 old(legacy::durable(Path::new(s(&plan,"output")?),&report))?;println!("{}",json!({"output":plan["output"],"failed_gates":report["failed_gates"].as_array().context("failed gates")?.len(),"future_bound_accepted":false,"new_memory_credit_bytes":0}));ensure!(report["failed_gates"].as_array().context("failed gates")?.is_empty(),"report contains failed qualification gates");Ok(())
}
#[cfg(test)]#[path="main_tests.rs"]mod tests;
