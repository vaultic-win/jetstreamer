//! Conservative role assignment. Current containment never becomes future acceptance.
use super::*;
#[derive(Clone,Debug)]
pub(super) struct Role {
 pub key:String,pub pool:String,pub kind:String,pub units:BTreeSet<String>,pub cgroup:String,
 pub per_instance:Option<u64>,pub parallel:Option<u64>,pub recovery:Option<u64>,pub aggregate:Option<u64>,
 pub funding:Value,pub sources:Vec<Value>,pub images:Vec<Value>,pub policy:Value,pub current_owner:Value,
 pub grammar:Value,pub unit_sources:Value,pub unit_profiles:Value,
}
fn optional(v:&Value,k:&str)->Result<Option<u64>> {if v[k].is_null(){Ok(None)}else{Ok(Some(n(v,k)?))}}
pub(super) fn roles(v:&Value)->Result<Vec<Role>> {
 let rows=v.as_array().context("typed role array")?;ensure!(rows.len()<=32768,"role count bound");let mut result=Vec::new();let mut keys=BTreeSet::new();
 for row in rows {exact_keys(row,&["claim_key","pool","kind","units","cgroup","per_instance_bytes","max_parallel","recovery_overlap_bytes","aggregate_budget_bytes","funding","source_files","images","future_policy","current_owner","launch_grammar","unit_source_sets","unit_profiles"])?;
 let key=s(row,"claim_key")?.to_owned();ensure!(!key.is_empty()&&keys.insert(key.clone()),"missing/duplicate reservation claim key");let pool=s(row,"pool")?.to_owned();ensure!(["shared64","native16","normal10","verifier96","actor","original199"].contains(&pool.as_str()),"unknown retained pool");let kind=s(row,"kind")?.to_owned();ensure!(["userspace","global-kernel"].contains(&kind.as_str()),"unknown role kind");let cgroup=s(row,"cgroup")?.to_owned();if kind=="global-kernel" {ensure!(cgroup.is_empty(),"global kernel is not a cgroup descendant credit");}else{capture::group_name(&cgroup)?;ensure!(cgroup!="/","unqualified root catch-all role forbidden");}
 let mut units=BTreeSet::new();for name in row["units"].as_array().context("exact allowed unit names")?{let name=name.as_str().context("unit string")?;capture::unit_name(name)?;ensure!(units.insert(name.into()),"duplicate unit route");}
 let sources=row["source_files"].as_array().context("source binding array")?.clone();let images=row["images"].as_array().context("image binding array")?.clone();
 result.push(Role{key,pool,kind,units,cgroup,per_instance:optional(row,"per_instance_bytes")?,parallel:optional(row,"max_parallel")?,recovery:optional(row,"recovery_overlap_bytes")?,aggregate:optional(row,"aggregate_budget_bytes")?,funding:row["funding"].clone(),sources,images,policy:row["future_policy"].clone(),current_owner:row["current_owner"].clone(),grammar:row["launch_grammar"].clone(),unit_sources:row["unit_source_sets"].clone(),unit_profiles:row["unit_profiles"].clone()});}
 Ok(result)
}
fn issue(issues:&mut Vec<Value>,kind:&str,role:&Role,reason:&str){issues.push(json!({"gate":kind,"claim_key":role.key,"reason":reason}));}
pub(super) fn future_arithmetic(rows:&[Role],host:u64,inputs:u64)->Vec<Value>{
 let mut issues=Vec::new();if host!=43_603_734_528||inputs!=2_684_354_560 {issues.push(json!({"gate":"historical-host-input-split","reason":"43.603GB historical host and2.5GiB separate input promises must remain disjoint"}));}
 if rows.iter().filter(|r|r.kind=="global-kernel").count()!=1 {issues.push(json!({"gate":"one-global-kernel-claim","reason":"exactly one uncharged global/kernel future reserve role required"}));}
 let mut pools=BTreeMap::<String,u64>::new();for r in rows {
 let Some((cap,count,recovery,budget))=r.per_instance.zip(r.parallel).zip(r.recovery).zip(r.aggregate).map(|(((a,b),c),d)|(a,b,c,d))else{issue(&mut issues,"unknown-future-budget",r,"missing per-instance/concurrency/recovery/aggregate bound");continue;};
 if cap==0||count==0||cap.checked_mul(count).and_then(|x|x.checked_add(recovery)).is_none_or(|peak|peak>budget){issue(&mut issues,"future-peak-undercharged",r,"parallel instances and simultaneous recovery must fit their distinct aggregate");}
 let entry=pools.entry(r.pool.clone()).or_default();match entry.checked_add(budget){Some(sum)=>*entry=sum,None=>issue(&mut issues,"pool-overflow",r,"reservation sum overflow")}
 }
 for (pool,limit)in[("shared64",64u64<<30),("native16",16u64<<30),("normal10",10u64<<30),("verifier96",96u64<<30),("original199",512u64<<20)]{if pools.get(pool).is_some_and(|v|*v>limit){issues.push(json!({"gate":"retained-pool-exceeded","pool":pool,"limit_bytes":limit,"reported_bytes":pools[pool]}));}}
 for(a,r)in rows.iter().enumerate(){for other in &rows[a+1..]{if r.kind=="userspace"&&other.kind=="userspace"&&(capture::contains(&r.cgroup,&other.cgroup)||capture::contains(&other.cgroup,&r.cgroup)){issues.push(json!({"gate":"duplicate-ancestor-descendant-charge","claims":[r.key,other.key],"reason":"one process cannot borrow both an aggregate and a child reservation"}));}}}issues
}
pub(super) fn process_role<'a>(process:&Value,rows:&'a[Role])->Result<&'a Role>{
 let kernel=process["kernel_thread"]==true;let group=s(process,"cgroup")?;let matches=rows.iter().filter(|r|if kernel{r.kind=="global-kernel"}else{r.kind=="userspace"&&capture::contains(&r.cgroup,group)}).collect::<Vec<_>>();ensure!(matches.len()==1,"process has missing or duplicate role reservation");Ok(matches[0])
}
fn finite(v:&Value)->Option<u64>{v.as_str().and_then(|s|s.parse().ok())}
fn validate_containment(role:&Role,process:&Value,groups:&Value)->Result<()> {
 if role.kind=="global-kernel" {ensure!(process["kernel_thread"]==true,"global kernel role cannot hide userspace");return Ok(());}
 let budget=role.aggregate.context("unbounded role/session/daemon")?;let group=s(process,"cgroup")?;ensure!(capture::contains(&role.cgroup,group),"systemd-launched child escaped funded controller cgroup");let limit=&groups[&role.cgroup];ensure!(finite(&limit["memory.max"])==Some(budget)&&limit["memory.swap.max"]=="0"&&finite(&limit["pids.max"]).is_some(),"actual selected ancestor hard controls differ");
 let membership=groups[group]["cgroup.procs"].as_array().context("actual process cgroup membership")?;ensure!(membership.contains(&process["pid"]),"process absent from declared cgroup.procs");
 let mut parent=Path::new(group).parent();while let Some(p)=parent{let name=p.to_str().context("ancestor UTF8")?;let entry=&groups[name];ensure!(!entry.is_null(),"ancestor missing from whole cgroup census");if name=="/"{break;}parent=p.parent();}Ok(())
}
fn image_matches(role:&Role,process:&Value,images:&BTreeMap<String,Value>)->Result<()> {
 if role.kind=="global-kernel"{return Ok(());}let path=s(&process["image"],"path")?;let binding=role.images.iter().find(|b|b["path"]==path).context("changed or unmapped executable including SDK/uploader child")?;let authenticated=images.get(s(binding,"path")?).context("executable image authentication missing")?;for key in["path","device","inode","bytes"]{ensure!(authenticated[key]==process["image"][key],"mapped executable identity differs: {key}");}Ok(())
}
pub(super) fn evaluate(endpoint:&Value,rows:&[Role],images:&BTreeMap<String,Value>)->Value {
 let mut issues=Vec::new();let mut assignments=Vec::new();let Some(processes)=endpoint["processes"].as_object()else{return json!({"issues":[{"gate":"missing-process-census"}],"assignments":[]});};
 for(pid,process)in processes {let result=(||->Result<&Role>{let r=process_role(process,rows)?;validate_containment(r,process,&endpoint["cgroups"])?;image_matches(r,process,images)?;validate_process_grammar(r,process)?;Ok(r)})();match result{Ok(r)=>assignments.push(json!({"pid":pid,"claim_key":r.key,"pool":r.pool,"cgroup":process["cgroup"]})),Err(e)=>issues.push(json!({"gate":"unmapped-or-unbounded-process","pid":pid,"cgroup":process["cgroup"],"reason":e.to_string()}))}}
 if let Some(units)=endpoint["units"].as_object(){for(name,v)in units {let queued=v["Job"].as_str().is_none_or(|s|!s.is_empty());let active=["MainPID","ControlPID"].iter().any(|k|v[k].as_str().and_then(|s|s.parse::<u64>().ok()).is_some_and(|p|p>0));let active=active||v["ActiveState"].as_str().is_some_and(|state|["active","activating","deactivating","reloading","refreshing"].contains(&state));if queued{issues.push(json!({"gate":"queued-work-not-qualified-at-finite-endpoint","unit":name,"job":v["Job"]}));}
 if (active||queued)&&rows.iter().filter(|r|r.units.contains(name)).count()!=1 {issues.push(json!({"gate":"unknown-active-or-queued-owner","unit":name,"native":v}));}}}
 if let Some(files)=endpoint["installed_unit_files"].as_object(){for(name,state)in files {if !matches!(state.as_str(),Some("masked"|"masked-runtime"))&&rows.iter().filter(|r|r.units.contains(name)).count()!=1 {issues.push(json!({"gate":"unmapped-future-installed-launch-route","unit":name,"state":state}));}}}
 if let Some(groups)=endpoint["cgroups"].as_object(){for(group,v)in groups {if let Some(members)=v["cgroup.procs"].as_array(){for pid in members {match processes.get(&pid.to_string()){None=>issues.push(json!({"gate":"cgroup-PID-not-in-process-census","cgroup":group,"pid":pid})),Some(p)if p["cgroup"]!=group.as_str()=>issues.push(json!({"gate":"cgroup-membership-migration-or-duplicate","cgroup":group,"pid":pid,"process_cgroup":p["cgroup"]})),Some(_)=>{}}}}}}
 for role in rows {if let Err(e)=validate_current_owner(role,endpoint){issue(&mut issues,"current-role-owner-or-sources-differ",role,&e.to_string());}}
 json!({"issues":issues,"assignments":assignments,"candidate_current_containment_complete":issues.is_empty(),"future_bound_accepted":false})
}
pub(super) fn validate_funding(rows:&[Role])->Vec<Value>{
 let mut issues=Vec::new();for role in rows {let checked=(||->Result<()>{ensure!(!role.sources.is_empty()&&!role.images.is_empty()||role.kind=="global-kernel","role source/image qualification missing");for b in &role.sources{authenticate_file(b)?;}
 ensure!(!role.funding.is_null()&&!role.policy.is_null(),"missing actual retained funding or future launch-policy qualification");let funding=bound(&role.funding)?;ensure!(funding["schema"]=="horizon-exact-role-retained-funding-proof-v1"&&funding["claim_key"]==role.key&&funding["pool"]==role.pool&&funding["aggregate_budget_bytes"].as_u64()==role.aggregate&&funding["all_original_promises_retained"]==true&&funding["resource_credit_bytes"]==0,"distinct actual retained reservation binding differs");let originals=funding["original_evidence"].as_array().context("actual original funding evidence")?;ensure!(!originals.is_empty(),"empty actual original funding evidence");for b in originals{bound(b)?;}
 let policy=bound(&role.policy)?;ensure!(policy["schema"]=="horizon-whole-role-future-launch-policy-proof-v1"&&policy["claim_key"]==role.key&&policy["source_files"]==json!(role.sources)&&policy["images"]==json!(role.images)&&policy["allowed_units"]==json!(role.units)&&policy["cgroup"]==role.cgroup&&policy["max_parallel"].as_u64()==role.parallel&&policy["recovery_overlap_bytes"].as_u64()==role.recovery&&policy["launch_grammar"]==role.grammar&&policy["unit_source_sets"]==role.unit_sources&&policy["unit_profiles"]==role.unit_profiles&&policy["all_launch_routes_qualified"]==true&&policy["all_descendants_or_separate_external_claims_funded"]==true,"complete future launcher/session/daemon policy not qualified");
 if role.kind=="global-kernel"{ensure!(funding["historical_host_fulfillment_reused"]==false&&policy["future_kernel_reserve_disjoint_from_historical_host"]==true,"historical global kernel bytes credited twice");}
 for child in policy["external_launch_claim_keys"].as_array().context("explicit PID1 launched child reservations")?{let key=child.as_str().context("external claim key")?;ensure!(key!=role.key&&rows.iter().any(|r|r.key==key),"external systemd child cannot borrow controller reservation");}
 if role.units.contains("horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service"){let live=bound(&policy["production_liveness"])?;validate_production_liveness(&live)?;}Ok(())})();if let Err(e)=checked{issue(&mut issues,"unqualified-role-future-policy",role,&e.to_string());}}issues
}
pub(super) fn validate_production_liveness(v:&Value)->Result<()> {ensure!(v["successful_production_upload_under_cap_qualified"]==true&&v["full_readback_verified"]==true&&v["canonical_sidecar_committed"]==true&&v["containment_only_fixture"]==false&&v["selected_coordinator_sha256"]=="1eede7d15cec7e5b1907ee44328caf2b20457ca8513472ca17e83fe3e08f9087"&&v["selected_uploader_sha256"]=="7b21414c1c105cefb18f5bf3ca8bb96759c14c529ea42232a70835bdc864b990","containment-only fixture or changed uploader image cannot prove production liveness");let evidence=v["actual_transport_readback_sidecar_evidence"].as_array().context("actual liveness evidence")?;ensure!(!evidence.is_empty(),"empty production transport/readback/sidecar evidence");for b in evidence{bound(b)?;}Ok(())}

fn validate_process_grammar(role:&Role,p:&Value)->Result<()>{
 if role.kind=="global-kernel"{return Ok(());}let allowed=role.grammar.as_array().context("unknown future launcher/argv grammar")?;
 ensure!(!allowed.is_empty()&&allowed.iter().all(|a|a.as_array().is_some_and(|args|!args.is_empty()&&args.iter().all(Value::is_string))),"unknown/unbounded future argv language");
 ensure!(allowed.contains(&p["argv"]),"actual process argv outside exact finite future launch grammar");Ok(())
}
fn validate_current_owner(role:&Role,e:&Value)->Result<()>{
 if role.kind=="global-kernel"{return Ok(());}let own_pid=std::process::id().to_string();let owners=role.current_owner.as_object().context("exact current owner map required, empty only when not executing")?;
 for(unit,want)in owners{ensure!(role.units.contains(unit),"owner from another role");let actual=&e["units"][unit];old(legacy::owner_matches(actual,want))?;let pid=s(want,"main_pid")?;let proc=&e["processes"][pid];ensure!(proc["start_ticks"]==want["start_ticks"]&&want["start_ticks"].is_u64(),"stale producer PID birth");ensure!(proc["cgroup"]==actual["ControlGroup"]&&capture::contains(&role.cgroup,s(proc,"cgroup")?),"owner process migrated or escaped");}
 for unit in &role.units {let actual=&e["units"][unit];ensure!(!actual.is_null(),"claimed unit omitted from native capture");let loaded=actual["LoadState"]!="not-found";let executing=["MainPID","ControlPID"].iter().any(|key|actual[key].as_str().and_then(|x|x.parse::<u64>().ok()).is_some_and(|p|p>0));ensure!(!executing||owners.contains_key(unit)||actual["Id"].as_str().is_some_and(|id|owners.contains_key(id))||unit==OWN&&actual["MainPID"]==own_pid&&actual["InvocationID"]==std::env::var("INVOCATION_ID")?,"executing unit lacks exact pinned IID/PID/birth");
 if loaded{let profile=role.unit_profiles.get(unit).context("missing exact native role controls/protections")?;ensure!(profile.is_object(),"typed native profile required");
 for key in["ControlGroup","Type","MemoryMax","MemoryHigh","MemoryMin","MemoryLow","MemorySwapMax","MemoryAccounting","TasksMax","Delegate","KillMode","NoNewPrivileges","ProtectControlGroups","User","Group","Restart","ExecStart","Slice"]{ensure!(profile.get(key)==actual.get(key),"role applicable native source/control/profile differs: {unit}:{key}");}
 if unit.ends_with(".service"){for key in["MemoryMax","MemorySwapMax","TasksMax","Delegate","KillMode","ExecStart"]{ensure!(actual[key].is_string(),"service hard/protection property missing: {key}");}}
 ensure!(role.unit_sources.get(unit).is_some()&&role.unit_sources[unit]==e["unit_sources"][unit],"exact unit fragment/source/drop-in set differs");}
 }
 Ok(())
}
pub(super) fn required_roles(rows:&[Role],plan:&Value)->Vec<Value>{
 let mut issues=Vec::new();let check=|issues:&mut Vec<Value>,unit:&str,pool:&str,cap:u64|{let matches=rows.iter().filter(|r|r.units.contains(unit)).collect::<Vec<_>>();if matches.len()!=1||matches[0].pool!=pool||matches[0].aggregate!=Some(cap){issues.push(json!({"gate":"omitted-or-changed-retained-role","unit":unit,"pool":pool,"required_bytes":cap}));}};
 let pins:Value=match serde_json::from_str(include_str!("local2-owners.json")){Ok(p)=>p,Err(e)=>return vec![json!({"gate":"invalid-inherited-owner-pins","reason":e.to_string()})]};
 if let Some(owners)=pins["owners"].as_array(){for owner in owners {if let(Some(unit),Some(cap))=(owner["unit"].as_str(),owner["whole_service_profile"]["MemoryMax"].as_str().and_then(|s|s.parse::<u64>().ok())){check(&mut issues,unit,"actor",cap);}}}
 if let Some(verifiers)=plan["retained_verification_roles"].as_array(){for row in verifiers{if let(Some(unit),Some(cap))=(row["unit"].as_str(),row["retained_cap_bytes"].as_u64()){check(&mut issues,unit,"verifier96",cap);}}}
 check(&mut issues,OWN,"native16",512u64<<20);
 let root=rows.iter().filter(|r|r.key=="root-native-outer").collect::<Vec<_>>();if root.len()!=1||root[0].pool!="native16"||root[0].aggregate!=Some(1u64<<30){issues.push(json!({"gate":"missing-separate-Root-outer-booking"}));}
 let native_retained=rows.iter().filter(|r|r.pool=="native16"&&r.key!="root-native-outer"&&!r.units.contains(OWN)).filter_map(|r|r.aggregate).try_fold(0u64,u64::checked_add);if native_retained!=Some(13_757_317_120){issues.push(json!({"gate":"missing-retained-native16-commitments","required_bytes":13_757_317_120u64}));}
 let normal=rows.iter().filter(|r|r.pool=="normal10").filter_map(|r|r.aggregate).try_fold(0u64,u64::checked_add);if normal!=Some(10u64<<30){issues.push(json!({"gate":"normal10-remainder-unreconciled","required_bytes":10u64<<30}));}
 check(&mut issues,"jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service","original199",512u64<<20);
 issues
}
pub(super) fn required_guards(rows:&[Role],guards:&Value)->Vec<Value>{let mut issues=Vec::new();if let Some(guards)=guards.as_array(){for guard in guards{let unit=&guard["current_successor_service"]["Id"];if rows.iter().filter(|r|r.pool=="normal10"&&r.aggregate==Some(1u64<<30)&&unit.as_str().is_some_and(|u|r.units.contains(u))).count()!=1{issues.push(json!({"gate":"current-DATA-guard-not-separately-funded","unit":unit}));}}}else{issues.push(json!({"gate":"missing-current-DATA-guard-census"}));}issues}
pub(super) fn authenticated_images(rows:&[Role],own_image:&Value)->(BTreeMap<String,Value>,Vec<Value>){
 let mut map=BTreeMap::<String,Value>::new();let mut issues=Vec::new();for role in rows{for binding in &role.images{let key=binding["path"].as_str().unwrap_or("").to_owned();let self_ref=binding["from_genuine_self_artifact"]==true;let digest=if self_ref{&own_image["sha256"]}else{&binding["sha256"]};if let Some(previous)=map.get(&key){if previous["sha256"]!=*digest{issue(&mut issues,"inconsistent-image-binding",role,"one executable path has different pinned digests");}continue;}let authenticated=if self_ref{if role.units.contains(OWN)&&key==IMAGE&&own_image["path"]==IMAGE{Ok(own_image.clone())}else{Err(anyhow::anyhow!("self artifact reference outside exact report role"))}}else{file_identity(binding)};match authenticated{Ok(v)=>{map.insert(key,v);},Err(e)=>issue(&mut issues,"image-authentication-failed",role,&e.to_string())}}}(map,issues)
}

#[cfg(test)]#[path="budget_tests.rs"]mod tests;
