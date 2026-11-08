//! Historical full-reader -> actual native issuer comparison capability.
//! Complete original/fresh raw documents are preserved; no deserialized bypass.
use super::*;
const READER: &str = "horizon-failed4-current-accounting-reader-20261104-v1.service";
const SLOT: u64 = 2 << 30;
type RetentionPlan = crate::fleet::charge136_retry0005::contract::Plan;
type Retained = crate::fleet::charge136_retry0005::retained_attempt::RetainedAttempt;

pub(super) struct Handoff {
    reader: Bound,
    request: Value,
    before: Value,
    origin: Value,
    proof: Value,
    completion: Value,
    sources: Value,
    retention_binding: Bound,
    retention: RetentionPlan,
    retained: Retained,
    old_helper: Value,
    new_helper: Value,
    candidate: held_candidate::Candidate,
}
fn slot(raw: &Value) -> Result<&Value> {
    let rows=raw["native_pool_suballocations"].as_array().context("native handoff complete pool")?;
    let slots=rows.iter().filter(|r|r["nonoverlapping_successor_slot"]==true).collect::<Vec<_>>();
    ensure!(slots.len()==1,"native handoff sole helper slot");
    let row=slots[0];
    ensure!(row["memory_max_bytes"]==SLOT && row["data_reservation_bytes"]==0
        && n(row,"pid")?>1 && n(row,"start_ticks")?>0,"native handoff exact2GiB/0DATA helper");
    let mut units=std::collections::BTreeSet::new();
    let mut iids=std::collections::BTreeSet::new();
    let mut sum=0u64;
    for r in rows {
        let unit=r["unit"].as_str().context("native pool unit")?;
        let iid=r["invocation_id"].as_str().context("native pool IID")?;
        ensure!(!unit.is_empty() && storage::hex(iid,32) && units.insert(unit) && iids.insert(iid),"native pool duplicate/crossed helper");
        let bytes=n(r,"memory_max_bytes")?;
        ensure!(bytes>0,"native pool unbounded/zero row");
        sum=sum.checked_add(bytes).context("native pool overflow")?;
    }
    ensure!(sum<=NORMAL_POOL && raw["native_pool_committed_bytes"]==sum,"native handoff preserves normal6GiB pool and exact commitment");
    Ok(row)
}
fn old_helper(proof: &Value, before: &Value, after: &Value) -> Result<Value> {
    let row=slot(after)?;
    ensure!(slot(before)?==row && row["unit"]==READER && row["invocation_id"]==proof["invocation_id"]
        && row["source_bindings"]==json!([proof["image"]])
        && proof["native"]["Id"]==READER && proof["native"]["InvocationID"]==row["invocation_id"]
        && proof["native"]["MainPID"].as_str()==Some(n(row,"pid")?.to_string().as_str()),
        "native historical reader helper proof/image/IID/PID/ticks crossed");
    for key in ["Id","InvocationID","MainPID","NRestarts","Restart","ActiveState","SubState",
        "Type","User","MemoryAccounting","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec","TasksMax","RuntimeMaxUSec"] {
        ensure!(row["native"][key]==proof["native"][key] && !proof["native"][key].is_null(),"native original helper native proof differs: {key}");
    }
    let image=to_bound(&proof["image"])?;
    let spec=to_bound(&proof["spec"])?;
    let argv=vec![image.path.display().to_string(),"read-failed4-current-accounting".into(),spec.path.display().to_string(),
        "--spec-sha256".into(),spec.sha256,"--self-sha256".into(),image.sha256];
    held::command(&row["native"],&image.path,&argv)?;
    Ok(row.clone())
}
fn completion_shape(c: &Value, proof: &Value, reader: &Bound) -> Result<()> {
    let native=&c["original_native"];
    ensure!(c["schema"]=="terminal199-parent-memory-original-reader-completion-v1"
        && c["reader_proof"]==json!(reader) && c["program"]==proof["image"]
        && c["original_outer_reaped"]==true && c["original_cgroup_empty"]==true && c["original_descriptors_drained"]==true
        && native["Id"]==READER && native["InvocationID"]==proof["invocation_id"]
        && native["MainPID"]=="0" && native["ControlPID"]=="0" && native["NRestarts"]=="0"
        && native["Job"]=="" && native["Result"]=="success" && native["ExecMainStatus"]=="0",
        "native original reader accepted completion changed/crossed");
    Ok(())
}
fn source_shape(proof:&Value,spec:&Value,sources:&Value,program:&Bound)->Result<()> {
    ensure!(spec["resource_accounting"]==*sources && spec["retention_plan"]==proof["retention_plan"]
        && spec["external_booking"]==proof["external_booking"] && proof["image"]==json!(program),
        "native historical reader exact original sources/retention/image differ");
    Ok(())
}
fn current_retired_role(v:&Value, proof:&Value)->Result<()> {
    let retained=v["InvocationID"]==proof["invocation_id"] && v["LoadState"]=="loaded"
        && ((v["ActiveState"]=="inactive" && v["SubState"]=="dead") || (v["ActiveState"]=="active" && v["SubState"]=="exited"));
    let collected=v["InvocationID"]=="" && v["LoadState"]=="not-found" && v["ActiveState"]=="inactive" && v["SubState"]=="dead";
    ensure!(v["Id"]==READER && (retained||collected) && v["MainPID"]=="0" && v["ControlPID"]=="0"
        && v["ControlGroup"]=="" && v["Job"]=="" && v["NRestarts"]=="0" && v["Restart"]=="no"
        && v["Result"]=="success" && v["ExecMainStatus"]=="0","native original reader replaced/unfinished/undrained");
    Ok(())
}
fn original_retired(proof: &Value, helper: &Value, completion:&Value) -> Result<()> {
    let journal=immutable(&to_bound(&completion["original_PID1_journal"])?)?;
    let iid=proof["invocation_id"].as_str().context("original reader IID")?;
    let rows=journal["original_rows"].as_array().context("original reader PID1 rows")?;
    let events=rows.iter().filter(|r|r["_PID"]=="1" && r["_UID"]=="0" && r["UNIT"]==READER
        && r["INVOCATION_ID"]==iid && r["MESSAGE_ID"]=="7ad2d189f7e94e70a38c781354912448").collect::<Vec<_>>();
    ensure!(events.len()==1 && events[0]["_BOOT_ID"].as_str()==Some(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().replace('-',"").as_str()),"original reader genuine PID1 success/boot missing");
    let out=ProcessCommand::new("/usr/bin/timeout").args(["--signal=TERM","--kill-after=2s","8s","/usr/bin/journalctl","--all","--no-pager","-ojson","-n","2","_PID=1","_UID=0",&format!("UNIT={READER}"),&format!("INVOCATION_ID={iid}"),"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"]).output()?;
    ensure!(out.status.success() && out.stderr.is_empty() && out.stdout.len()<=65536,"original reader PID1 native query");
    let actual=std::str::from_utf8(&out.stdout)?.lines().map(serde_json::from_str::<Value>).collect::<std::result::Result<Vec<_>,_>>()?;
    ensure!(actual.len()==1 && actual[0]==*events[0],"original reader PID1 success changed or crossed");
    // Query only this fixed public helper role; never an original199 body or FD.
    let out=ProcessCommand::new("/usr/bin/timeout").args(["--signal=TERM","--kill-after=2s","8s","/usr/bin/systemctl","--system","show",READER,"--no-pager",
        "--property=Id,LoadState,InvocationID,MainPID,ControlPID,ControlGroup,Job,NRestarts,Restart,ActiveState,SubState,Result,ExecMainStatus"])
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS").env_remove("SYSTEMD_HOST").output()?;
    ensure!(out.status.success() && out.stderr.is_empty() && out.stdout.len()<=65536,"native original reader current role query");
    let mut m=serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k,v)=line.split_once('=').context("native reader current framing")?;
        ensure!(m.insert(k.into(),json!(v)).is_none(),"duplicate original reader native field");
    }
    let v=Value::Object(m);
    current_retired_role(&v,proof)?;
    match fs::symlink_metadata(format!("/proc/{}",n(helper,"pid")?)) {
        Err(e) if e.kind()==std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(_) => anyhow::bail!("native original reader PID is still present; no historical slot handoff"),
    }
    Ok(())
}
/// Pure exact comparison projection. Its caller must own a private Handoff.
/// Never writes either raw document, removes a claim, or increases pool budget.
fn comparison(before: &Value, semantic_after: &Value, old: &Value, new: &Value) -> Result<Value> {
    ensure!(old["unit"]==READER && new["unit"]==ISSUER && old["unit"]!=new["unit"]
        && old["invocation_id"]!=new["invocation_id"] && old["pid"]!=new["pid"]
        && slot(before)?==old && slot(semantic_after)?==new,"native handoff exact old/new slot crossed");
    let foreign=|v:&Value| -> Result<Vec<Value>> { Ok(v["native_pool_suballocations"].as_array().context("native handoff pool array")?
        .iter().filter(|r|r["nonoverlapping_successor_slot"]!=true).cloned().collect()) };
    ensure!(foreign(before)?==foreign(semantic_after)? && before["native_pool_committed_bytes"]==semantic_after["native_pool_committed_bytes"],
        "native handoff changed foreign pool row or commitment");
    let mut out=semantic_after.clone();
    let rows=out["native_pool_suballocations"].as_array_mut().context("native comparison pool")?;
    for row in rows.iter_mut() { if row["nonoverlapping_successor_slot"]==true { *row=old.clone(); } }
    rows.sort_by(|a,b|a["unit"].as_str().cmp(&b["unit"].as_str()));
    ensure!(out["native_pool_suballocations"]==before["native_pool_suballocations"],"native handoff complete pool changed");
    unchanged_claims(before,&out)?;
    Ok(out)
}
const CENSUS_FIELDS:[&str;12]=["ActiveState","ControlGroup","ExecMainStatus","ExecStart","Id","InvocationID","LoadState","MainPID","NRestarts","Result","SubState","Type"];
fn exact_helper_census(row:&Value,helper:&Value)->Result<()> {
 let object=row.as_object().context("native handoff census row")?;
 ensure!(object.len()==CENSUS_FIELDS.len() && CENSUS_FIELDS.iter().all(|key|object.contains_key(*key)),"native helper census exact field set");
 for key in CENSUS_FIELDS { ensure!(row[key]==helper["native"][key] && row[key].is_string(),"native helper census differs from authenticated helper: {key}"); }
 ensure!(row["Id"]==helper["unit"] && row["InvocationID"]==helper["invocation_id"] && row["MainPID"].as_str()==Some(n(helper,"pid")?.to_string().as_str()),"native helper census crossed role/IID/PID");
 Ok(())
}
fn exact_candidate_row(row:&Value,capture:&Value,exact_fields:bool,field:&str)->Result<()> {
 let object=row.as_object().with_context(||format!("native candidate {field} row missing"))?;
 let producer=if exact_fields {"comparison_native_census"} else {"comparison_discovery"};
 let expected=capture[producer].as_object().context("actual private candidate producer snapshot absent")?;
 let actual_keys=object.keys().collect::<std::collections::BTreeSet<_>>();
 let expected_keys=expected.keys().collect::<std::collections::BTreeSet<_>>();
 ensure!(actual_keys==expected_keys,"native candidate {field} exact producer field set differs: expected={expected_keys:?} actual={actual_keys:?}");
 for (key,value) in expected {
  ensure!(object.get(key)==Some(value) && value.is_string(),
    "native candidate {field} full producer field differs: key={key} expected={value} actual={}",row[key]);
 }
 for key in CENSUS_FIELDS {
  ensure!(row[key].is_string() && row[key]==capture["native"][key],
   "native candidate {field} differs from actual original held capture: key={key} expected={} actual={}",capture["native"][key],row[key]);
 }
 ensure!(row["Id"]==ACTOR && row["InvocationID"]==capture["iid"]
  && row["MainPID"].as_str()==Some(n(capture,"pid")?.to_string().as_str()),"native candidate {field} role/IID/PID crossed");
 Ok(())
}
fn foreign_membership(a:&serde_json::Map<String,Value>,b:&serde_json::Map<String,Value>,old_name:&str,new_name:&str,field:&str)->Result<()> {
 let foreign_a=a.keys().filter(|k|k.as_str()!=old_name).cloned().collect::<std::collections::BTreeSet<_>>();
 let foreign_b=b.keys().filter(|k|k.as_str()!=new_name && k.as_str()!=ACTOR).cloned().collect::<std::collections::BTreeSet<_>>();
 let missing=foreign_a.difference(&foreign_b).cloned().collect::<Vec<_>>();
 let unexpected=foreign_b.difference(&foreign_a).cloned().collect::<Vec<_>>();
 ensure!(missing.is_empty() && unexpected.is_empty(),
  "native handoff foreign {field} membership changed: missing={missing:?} unexpected={unexpected:?}; permitted_removed={old_name} permitted_added=[{new_name},{ACTOR}]");
 Ok(())
}
fn compare_native_census(before:&Value,fresh:&Value,old:&Value,new:&Value,capture:&Value,comparison:&mut Value)->Result<()> {
 for field in ["native_before","native_after"] {
  let a=before[field].as_object().with_context(||format!("native historical {field} census missing"))?;
  let b=fresh[field].as_object().with_context(||format!("native fresh {field} census missing"))?;
  let old_name=old["unit"].as_str().context("old native helper unit")?;
  let new_name=new["unit"].as_str().context("new native helper unit")?;
  ensure!(old_name==READER && new_name==ISSUER && old_name!=new_name && !a.contains_key(new_name) && !b.contains_key(old_name),
   "native handoff {field} crossed or duplicate helper membership; original_keys={:?} fresh_keys={:?}",a.keys().collect::<Vec<_>>(),b.keys().collect::<Vec<_>>());
  ensure!(!a.contains_key(ACTOR),"native candidate was already present in original {field}; no induction permitted");
  exact_helper_census(a.get(old_name).context("original helper census absent")?,old)?;
  exact_helper_census(b.get(new_name).context("fresh helper census absent")?,new)?;
  exact_candidate_row(b.get(ACTOR).with_context(||format!("native candidate {field} absent; fresh_keys={:?}",b.keys().collect::<Vec<_>>()))?,capture,true,field)?;
  foreign_membership(a,b,old_name,new_name,field)?;
  let out=comparison[field].as_object_mut().context("native comparison census absent")?;
  ensure!(*out==*b,"native comparison altered before exact helper/candidate handoff");
  ensure!(out.remove(new_name)==b.get(new_name).cloned() && out.insert(old_name.into(),a[old_name].clone()).is_none(),"native comparison exact helper substitution failed");
  ensure!(out.remove(ACTOR)==b.get(ACTOR).cloned(),"native comparison exact held candidate induction failed");
  // Only comparison identity membership changes. Actual fresh census remains
  // intact; foreign rows stay actual and existing guard policy validates them.
  for key in b.keys().filter(|k|k.as_str()!=new_name && k.as_str()!=ACTOR) {
   ensure!(out.get(key)==b.get(key),"native handoff altered a foreign {field} census row: {key}");
  }
 }
 Ok(())
}
fn compare_discovery_membership(before:&Value,fresh:&Value,old:&Value,new:&Value,capture:&Value)->Result<()> {
 for field in ["workload_discovery_before","workload_discovery_after"] {
  let a=before[field].as_object().with_context(||format!("native historical {field} missing"))?;
  let b=fresh[field].as_object().with_context(||format!("native fresh {field} missing"))?;
  let old_name=old["unit"].as_str().context("historical discovery helper")?;
  let new_name=new["unit"].as_str().context("fresh discovery helper")?;
  ensure!(!a.contains_key(ACTOR) && !a.contains_key(new_name) && !b.contains_key(old_name)
   && a.contains_key(old_name) && b.contains_key(new_name),"native {field} crossed/missing helper or previously present candidate");
  exact_candidate_row(b.get(ACTOR).with_context(||format!("native held candidate missing in {field}; fresh_keys={:?}",b.keys().collect::<Vec<_>>()))?,capture,false,field)?;
  for (name,helper,rows) in [(old_name,old,a),(new_name,new,b)] {
   for key in CENSUS_FIELDS {
    ensure!(rows[name][key].is_string() && rows[name][key]==helper["native"][key],
     "native {field} actual helper discovery differs: unit={name} key={key}");
   }
  }
  // Discovery contains a wider native property record. Bind every shared census
  // field, and the same19 profile fields covered_held itself authenticates.
  for key in ["Restart","MemoryAccounting","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec","TasksMax","User"] {
   ensure!(b[ACTOR][key].is_string() && b[ACTOR][key]==capture["native"][key],"native candidate {field} discovery profile differs: {key}");
  }
  foreign_membership(a,b,old_name,new_name,field)?;
 }
 Ok(())
}

impl Handoff {
    pub(super) fn load(reader:&Bound, request:&memory::model::Request, view:&memory::VerifiedParentMemory,
        sources:&Value, clock:u64, candidate:held_candidate::Candidate) -> Result<Self> {
        // The preceding constructor authenticates original request/qualification,
        // reader completion/PID1 journal/drain and original300s freshness.
        ensure!(view.evidence()["request"]==json!(request),"native handoff genuine opaque request crossed");
        let (before,origin)=original_reader_before(Some(reader),request,view,clock)?.context("native historical reader absent")?;
        let proof=immutable(reader)?;
        let spec=immutable(&to_bound(&proof["spec"])?)?;
        let completion=immutable(&request.current_reader_acceptance)?;
        completion_shape(&completion,&proof,reader)?;
        source_shape(&proof,&spec,sources,&request.reader_program.program)?;
        let original_before=immutable(&to_bound(&proof["accounting_before"])?)?;
        let old_helper=old_helper(&proof,&original_before,&before)?;
        candidate.require_original_absent(&original_before)?;
        candidate.require_original_absent(&before)?;
        // Raw originals independently preserve the identical actual helper.
        for key in ["original_raw_builder_before","original_raw_builder_after"] {
            let raw=immutable(&to_bound(&proof[key])?)?;
            ensure!(slot(&raw)?==&old_helper,"native original raw helper differs");
            candidate.require_original_absent(&raw)?;
        }
        let retention_binding=to_bound(&proof["retention_plan"])?;
        let retention:RetentionPlan=serde_json::from_value(immutable(&retention_binding)?)?;
        let retained=crate::fleet::charge136_retry0005::retained_attempt::actual(&retention)?;
        for (raw,projected) in [("original_raw_builder_before","accounting_before"),("original_raw_builder_after","accounting")] {
            let raw=immutable(&to_bound(&proof[raw])?)?;
            let expected=crate::fleet::charge136_retry0005::retained_attempt::project(&retention,&raw,&retained)?;
            ensure!(expected==immutable(&to_bound(&proof[projected])?)?,"native original exact retention projection changed");
        }
        original_retired(&proof,&old_helper,&completion)?;
        let new_helper=epoch186::accounting::native163_current_helper()?;
        Ok(Self{reader:reader.clone(),request:json!(request),before,origin,proof,completion,sources:sources.clone(),
            retention_binding,retention,retained,old_helper,new_helper,candidate})
    }
    pub(super) fn before(&self)->&Value { &self.before }
    pub(super) fn origin(&self)->&Value { &self.origin }
    pub(super) fn evidence(&self)->Value {
        json!({"schema":"epoch163-native-historical-reader-helper-comparison-v1","reader":self.reader,
            "original_completion":self.request["current_reader_acceptance"],"retention_plan":self.retention_binding,
            "original_helper":self.old_helper,"actual_issuer_helper":self.new_helper,
            "exact_held_candidate_induction":self.candidate.evidence(),
            "normal_pool_bytes":NORMAL_POOL,"helper_bytes":SLOT,"helper_DATA_bytes":0,
            "comparison_only":true,"memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0})
    }
    pub(super) fn revalidate(&self,request:&memory::model::Request,view:&memory::VerifiedParentMemory,clock:u64)->Result<()> {
        ensure!(json!(request)==self.request && immutable(&self.reader)?==self.proof
            && immutable(&request.current_reader_acceptance)?==self.completion
            && immutable(&self.retention_binding)?==serde_json::to_value(&self.retention)?
            && crate::fleet::charge136_retry0005::retained_attempt::actual(&self.retention)?==self.retained
            && epoch186::accounting::native163_current_helper()?==self.new_helper,"native handoff source/retention/actual issuer changed");
        let (before,origin)=original_reader_before(Some(&self.reader),request,view,clock)?.context("native before absent")?;
        ensure!(before==self.before && origin==self.origin,"native original before/clock changed");
        self.candidate.revalidate()?;
        original_retired(&self.proof,&self.old_helper,&self.completion)
    }
    pub(super) fn project(&self,raw:&Value)->Result<(Value,Value)> {
        ensure!(epoch186::accounting::native163_current_helper()?==self.new_helper && slot(raw)?==&self.new_helper,
            "native fresh raw actual issuer helper changed/crossed");
        original_retired(&self.proof,&self.old_helper,&self.completion)?;
        self.candidate.revalidate()?;
        let actual=crate::fleet::charge136_retry0005::retained_attempt::actual(&self.retention)?;
        ensure!(actual==self.retained,"native actual retention changed before fresh projection");
        let semantic=crate::fleet::charge136_retry0005::retained_attempt::project(&self.retention,raw,&actual)?;
        let mut compared=comparison(&self.before,&semantic,&self.old_helper,&self.new_helper)?;
        compare_native_census(&self.before,&semantic,&self.old_helper,&self.new_helper,&self.candidate.capture(),&mut compared)?;
        compare_discovery_membership(&self.before,&semantic,&self.old_helper,&self.new_helper,&self.candidate.capture())?;
        epoch186::accounting::stable_guard_basis(&self.sources,&self.before,&compared)?;
        Ok((semantic,compared))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn helper(unit:&str,iid:char,pid:u64)->Value {
        json!({"unit":unit,"invocation_id":iid.to_string().repeat(32),"pid":pid,"start_ticks":pid+100,
            "memory_max_bytes":SLOT,"data_reservation_bytes":0,"nonoverlapping_successor_slot":true,
            "native":{"Id":unit},"source_bindings":[{"path":"/actual/helper","sha256":"c".repeat(64)}]})
    }
    fn reports()->(Value,Value,Value,Value) {
        let old=helper(READER,'a',10); let new=helper(ISSUER,'b',20);
        let foreign=json!({"unit":"foreign.service","invocation_id":"d".repeat(32),"memory_max_bytes":512u64<<20,"data_reservation_bytes":19});
        let base=json!({"native_pool_suballocations":[foreign,old],"native_pool_committed_bytes":SLOT+(512u64<<20),
            "current_unique_owner_census":[],"current_owner_hard_limits":{},"active_peer_allocations":[{"unit":"failed4-retained","memory_max_bytes":7,"data_reservation_bytes":11}],
            "projected_obligations":[{"claim_key":"existing","outstanding_bytes":13}],"current_replay_cpu_quota_micros":17,
            "protected_existing_DATA_bytes":23,"standing_frontier_bytes":29,"confirmed_DATA_floor_bytes":31,"active_trial_memory_promises_bytes":37});
        let mut after=base.clone(); after["native_pool_suballocations"][1]=new.clone();
        (base,after,old,new)
    }
    fn census_fixture()->(Value,Value,Value,Value,Value) {
      fn helper_row(unit:&str,iid:&str,pid:u64)->Value {
       let mut native=serde_json::Map::new();for key in CENSUS_FIELDS {native.insert(key.into(),json!("value"));}
       native.insert("Id".into(),json!(unit));native.insert("InvocationID".into(),json!(iid));native.insert("MainPID".into(),json!(pid.to_string()));
       json!({"unit":unit,"invocation_id":iid,"pid":pid,"native":native})
      }
      let old=helper_row(READER,&"a".repeat(32),123);let new=helper_row(ISSUER,&"b".repeat(32),124);
      let actor=helper_row(ACTOR,&"c".repeat(32),125);
      let mut capture=json!({"iid":actor["invocation_id"],"pid":125,"start_ticks":199,"native":actor["native"]});
      for key in ["Restart","MemoryAccounting","MemoryMax","MemorySwapMax","CPUQuotaPerSecUSec","TasksMax","User"] {capture["native"][key]=json!("actual-profile");}
      let mut a=json!({"native_before":{},"native_after":{},"workload_discovery_before":{},"workload_discovery_after":{}});let mut b=a.clone();
      const FULL:&str="ActiveState,AmbientCapabilities,CPUQuotaPerSecUSec,CapabilityBoundingSet,ControlGroup,ControlPID,Delegate,ExecMainCode,ExecMainExitTimestamp,ExecMainPID,ExecMainStartTimestamp,ExecMainStatus,ExecStart,Group,Id,InvocationID,Job,KillMode,LoadState,MainPID,MemoryAccounting,MemoryHigh,MemoryMax,MemorySwapMax,NRestarts,NoNewPrivileges,PrivateNetwork,ProtectHome,ProtectSystem,ReadWritePaths,RemainAfterExit,Restart,Result,RuntimeMaxUSec,SubState,TasksMax,Type,User";
      const DISCOVERY:&str="Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ControlGroup,ExecStart,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,TriggeredBy,Triggers,Unit,User,Type";
      for (member,fields) in [("comparison_native_census",FULL),("comparison_discovery",DISCOVERY)] {
       let mut row=serde_json::Map::new();for key in fields.split(',') {
        row.insert(key.into(),capture["native"].get(key).cloned().unwrap_or(json!("actual-extended-property")));
       }
       capture[member]=Value::Object(row);
      }
      for field in ["native_before","native_after","workload_discovery_before","workload_discovery_after"] {
       a[field][READER]=old["native"].clone();a[field]["foreign.service"]=json!({"actual":"original"});
       b[field][ISSUER]=new["native"].clone();b[field]["foreign.service"]=json!({"actual":"fresh"});
       b[field][ACTOR]=capture[if field.starts_with("native_") {"comparison_native_census"} else {"comparison_discovery"}].clone();
      }
      (a,b,old,new,capture)
    }
    #[test]
    fn exact_new_held_candidate_and_helper_induction_preserves_every_original_and_foreign_row() {
      let (a,b,old,new,capture)=census_fixture();let originals=(a.clone(),b.clone());let mut compared=b.clone();
      compare_native_census(&a,&b,&old,&new,&capture,&mut compared).unwrap();
      compare_discovery_membership(&a,&b,&old,&new,&capture).unwrap();
      assert_eq!((a.clone(),b.clone()),originals);
      for field in ["native_before","native_after"] {
       assert!(compared[field].get(ISSUER).is_none());assert!(compared[field].get(ACTOR).is_none());
       assert_eq!(compared[field][READER],old["native"]);assert_eq!(compared[field]["foreign.service"],b[field]["foreign.service"]);
      }
      // Discovery/raw reports and all resource promises remain actual; this
      // pure test cannot construct Candidate or Handoff runtime capabilities.
      assert_eq!(compared["workload_discovery_after"],b["workload_discovery_after"]);
    }
    #[test]
    fn candidate_induction_rejects_missing_crossed_changed_duplicate_or_unrelated_membership() {
      let (a,b,old,new,capture)=census_fixture();
      for field in ["native_before","native_after"] {
       let mut extra=b.clone();extra[field]["unexpected.service"]=json!({});
       let error=compare_native_census(&a,&extra,&old,&new,&capture,&mut extra.clone()).unwrap_err().to_string();
       assert!(error.contains("unexpected.service") && error.contains("unexpected="),"{error}");
       let mut missing=b.clone();missing[field].as_object_mut().unwrap().remove("foreign.service");
       let error=compare_native_census(&a,&missing,&old,&new,&capture,&mut missing.clone()).unwrap_err().to_string();
       assert!(error.contains("foreign.service") && error.contains("missing="),"{error}");
       for key in capture["comparison_native_census"].as_object().unwrap().keys() {
        let mut changed=b.clone();changed[field][ACTOR][key]=json!("crossed");
        assert!(compare_native_census(&a,&changed,&old,&new,&capture,&mut changed.clone()).is_err(),"candidate {field} {key}");
        let mut removed=b.clone();removed[field][ACTOR].as_object_mut().unwrap().remove(key);
        assert!(compare_native_census(&a,&removed,&old,&new,&capture,&mut removed.clone()).is_err(),"missing candidate {field} {key}");
       }
       for key in CENSUS_FIELDS {
        let mut helper=b.clone();helper[field][ISSUER][key]=json!("crossed");
        assert!(compare_native_census(&a,&helper,&old,&new,&capture,&mut helper.clone()).is_err(),"helper {field} {key}");
       }
       let mut no_actor=b.clone();no_actor[field].as_object_mut().unwrap().remove(ACTOR);
       assert!(compare_native_census(&a,&no_actor,&old,&new,&capture,&mut no_actor.clone()).is_err());
       let mut present=a.clone();present[field][ACTOR]=b[field][ACTOR].clone();
       assert!(compare_native_census(&present,&b,&old,&new,&capture,&mut b.clone()).is_err());
       let mut extra_field=b.clone();extra_field[field][ACTOR]["foreign_field"]=json!("x");
       assert!(compare_native_census(&a,&extra_field,&old,&new,&capture,&mut extra_field.clone()).is_err());
       let mut duplicate=b.clone();duplicate[field][READER]=old["native"].clone();
       assert!(compare_native_census(&a,&duplicate,&old,&new,&capture,&mut duplicate.clone()).is_err());
      }
      for key in ["iid","pid"] {let mut crossed=capture.clone();crossed[key]=json!("crossed");assert!(compare_native_census(&a,&b,&old,&new,&crossed,&mut b.clone()).is_err());}
      let mut altered=b.clone();altered["native_after"]["foreign.service"]=json!({"tampered":true});
      assert!(compare_native_census(&a,&b,&old,&new,&capture,&mut altered).is_err());
    }
    #[test]
    fn candidate_induction_requires_both_complete_fresh_discoveries_and_no_foreign_membership_delta() {
      let (a,b,old,new,capture)=census_fixture();
      for field in ["workload_discovery_before","workload_discovery_after"] {
       let mut extra=b.clone();extra[field]["unrelated.service"]=json!({});
       assert!(compare_discovery_membership(&a,&extra,&old,&new,&capture).unwrap_err().to_string().contains("unrelated.service"));
       let mut missing=b.clone();missing[field].as_object_mut().unwrap().remove("foreign.service");
       assert!(compare_discovery_membership(&a,&missing,&old,&new,&capture).unwrap_err().to_string().contains("foreign.service"));
       let mut no_actor=b.clone();no_actor[field].as_object_mut().unwrap().remove(ACTOR);
       assert!(compare_discovery_membership(&a,&no_actor,&old,&new,&capture).is_err());
       let mut present=a.clone();present[field][ACTOR]=b[field][ACTOR].clone();
       assert!(compare_discovery_membership(&present,&b,&old,&new,&capture).is_err());
       for key in capture["comparison_discovery"].as_object().unwrap().keys() {
        let mut changed=b.clone();changed[field][ACTOR][key]=json!("changed");
        assert!(compare_discovery_membership(&a,&changed,&old,&new,&capture).is_err(),"{field} {key}");
       }
      }
    }

    #[test]
    fn original_reader_collection_requires_genuine_prior_completion_and_no_replacement_role() {
        let proof=json!({"invocation_id":"a".repeat(32)});
        let clean=json!({"Id":READER,"LoadState":"not-found","InvocationID":"","MainPID":"0","ControlPID":"0","ControlGroup":"","Job":"","NRestarts":"0","Restart":"no","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead"});
        current_retired_role(&clean,&proof).unwrap();
        for (key,value) in [("InvocationID","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),("LoadState","loaded"),("MainPID","123"),("Result","exit-code"),("Job","1"),("NRestarts","1")] {
            let mut bad=clean.clone();bad[key]=json!(value);assert!(current_retired_role(&bad,&proof).is_err(),"{key}");
        }
        let mut retained=clean;retained["LoadState"]=json!("loaded");retained["InvocationID"]=proof["invocation_id"].clone();
        current_retired_role(&retained,&proof).unwrap();
    }

    #[test]
    fn exact_historical_slot_comparison_preserves_raw_and_all_foreign_promises() {
        let (before,after,old,new)=reports(); let original=(before.clone(),after.clone());
        let compared=comparison(&before,&after,&old,&new).unwrap();
        assert_eq!(compared,before); assert_eq!((before,after),original);
        // This pure projection constructs no Handoff or runtime authority.
    }
    #[test]
    fn crossed_missing_duplicate_cap_debt_or_foreign_slot_rejects() {
        let (before,after,old,new)=reports();
        for (field,val) in [("unit",json!(READER)),("invocation_id",json!("f".repeat(32))),
            ("pid",json!(99)),("start_ticks",json!(999)),("memory_max_bytes",json!(SLOT-1)),
            ("data_reservation_bytes",json!(1)),("source_bindings",json!([]))] {
            let mut changed=after.clone(); changed["native_pool_suballocations"][1][field]=val;
            assert!(comparison(&before,&changed,&old,&new).is_err(),"{field}");
        }
        let mut foreign=after.clone();foreign["native_pool_suballocations"][0]["data_reservation_bytes"]=json!(0);
        assert!(comparison(&before,&foreign,&old,&new).is_err());
        let mut duplicate=after.clone();duplicate["native_pool_suballocations"].as_array_mut().unwrap().push(new.clone());
        assert!(comparison(&before,&duplicate,&old,&new).is_err());
        let mut missing=after.clone();missing["native_pool_suballocations"].as_array_mut().unwrap().remove(1);
        assert!(comparison(&before,&missing,&old,&new).is_err());
        let mut cap=after.clone();cap["native_pool_committed_bytes"]=json!(6u64<<30);
        assert!(comparison(&before,&cap,&old,&new).is_err());
        for field in ["active_peer_allocations","projected_obligations","protected_existing_DATA_bytes",
            "current_replay_cpu_quota_micros","active_trial_memory_promises_bytes"] {
            let mut changed=after.clone();changed[field]=json!(0);
            assert!(comparison(&before,&changed,&old,&new).is_err(),"{field}");
        }
    }
    #[test]
    fn original_reader_completion_cannot_cross_or_omit_real_drains() {
        let reader=Bound{path:"/real/proof.json".into(),sha256:"a".repeat(64)};
        let proof=json!({"image":{"path":"/real/helper","sha256":"b".repeat(64)},"invocation_id":"c".repeat(32)});
        let completion=json!({"schema":"terminal199-parent-memory-original-reader-completion-v1","reader_proof":reader,
            "program":proof["image"],"original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,
            "original_native":{"Id":READER,"InvocationID":proof["invocation_id"],"MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","Result":"success","ExecMainStatus":"0"}});
        completion_shape(&completion,&proof,&reader).unwrap();
        for field in ["reader_proof","program","original_outer_reaped","original_cgroup_empty","original_descriptors_drained"] {
            let mut changed=completion.clone();changed[field]=json!(false);
            assert!(completion_shape(&changed,&proof,&reader).is_err(),"{field}");
        }
        let mut changed=completion;changed["original_native"]["InvocationID"]=json!("e".repeat(32));
        assert!(completion_shape(&changed,&proof,&reader).is_err());
    }
    #[test]
    fn crossed_retention_sources_program_or_original_booking_rejects() {
        let program=Bound{path:"/real/helper".into(),sha256:"a".repeat(64)};
        let bound=|path:&str|json!({"path":path,"sha256":"b".repeat(64)});
        let sources=json!({"observer":bound("/real/observer"),"guards":[bound("/real/guard")]});
        let proof=json!({"retention_plan":bound("/real/retention"),"external_booking":bound("/real/booking"),"image":program});
        let spec=json!({"retention_plan":proof["retention_plan"],"external_booking":proof["external_booking"],"resource_accounting":sources});
        source_shape(&proof,&spec,&sources,&program).unwrap();
        for key in ["retention_plan","external_booking","resource_accounting"] {
            let mut changed=spec.clone();changed[key]=json!({"path":"/foreign","sha256":"c".repeat(64)});
            assert!(source_shape(&proof,&changed,&sources,&program).is_err(),"{key}");
        }
        let mut changed=proof;changed["image"]["sha256"]=json!("d".repeat(64));
        assert!(source_shape(&changed,&spec,&sources,&program).is_err());
    }
}
