//! The issuer calls complete maintenance admission; it never accepts available
//! memory, growth, omitted owners or a caller's boolean as resource evidence.
use super::*;
const METADATA:u64=32<<20;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema:String,recovery_plan:BoundFile,plan_issuance:BoundFile,assembler:BoundFile,
    producer_unit_file:BoundFile,guard_unit_file:BoundFile,resource_basis:Value,capacity_output:PathBuf,
}
fn minimum_disk(p:&Value)->Result<u64> {
    let original=read(&serde_json::from_value(p["original_plan"].clone())?)?;
    ensure!(p["original_plan"]["sha256"]==OLD_PLAN,"204 admission original plan digest");
    n(&original,"protected_existing_floor_bytes")
}
pub(super) fn candidate(stage:downstream::Stage,bytes:u64,floor:u64)->Result<maintenance_capacity::Candidate> {
    let (additional,memory)=match stage {
        downstream::Stage::Assembly=>(OUTPUT_MAX.checked_add(METADATA).context("204 assembly disk overflow")?,MEMORY+GUARD_MEMORY),
        downstream::Stage::Full=>(OUTPUT_MAX.checked_add(METADATA).context("204 scan disk overflow")?,MEMORY),
        downstream::Stage::Plugin=>(128<<20,MEMORY),
        downstream::Stage::Import=>(bytes.checked_add(METADATA).context("204 import disk overflow")?,16<<30),
        downstream::Stage::Upload=>(1<<30,16<<30),
    };
    ensure!(floor>0 && bytes<=OUTPUT_MAX,"204 candidate bounds missing");
    Ok(maintenance_capacity::Candidate{additional_bytes:additional,memory_max_bytes:memory,minimum_protected_disk_bytes:floor})
}
fn unit_file(b:&BoundFile,p:&Value,plan:&BoundFile,assembler:&BoundFile,guard:bool)->Result<()> {
    let text=String::from_utf8(sealed(b,1<<20)?)?;
    let name=if guard{GUARD}else{UNIT};
    ensure!(b.path==Path::new("/etc/systemd/system").join(name),"204 assembly unit fragment scope");
    let expected=format!("ExecStart={} {} --plan-sha256 {} --self-sha256 {}{}",assembler.path.display(),
        plan.path.display(),plan.sha256,assembler.sha256,if guard{" --guard"}else{""});
    let mut keys=BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|s|!s.is_empty()&&!s.starts_with('#')&&!s.starts_with('[')) {
        let (key,value)=line.split_once('=').context("204 malformed unit fragment")?;
        ensure!(keys.insert(key,value).is_none(),"204 duplicate unit directive");
    }
    for (key,value) in [("ExecStart",expected.as_str()),("Type","exec"),("User","root"),("Restart","no"),
        ("ProtectSystem","strict"),("ProtectHome","read-only"),("PrivateNetwork","yes"),
        ("ReadWritePaths",ROOT),("NoNewPrivileges","yes"),("MemorySwapMax","0"),
        ("CapabilityBoundingSet","CAP_DAC_OVERRIDE CAP_SYS_PTRACE"),("AmbientCapabilities","CAP_DAC_OVERRIDE CAP_SYS_PTRACE")] {
        ensure!(keys.get(key)==Some(&value),"204 effective fragment differs: {key}");
    }
    let max=if guard{GUARD_MEMORY}else{MEMORY}.to_string();
    ensure!(keys.get("MemoryMax")==Some(&max.as_str()) && p["executable_sha256"]==assembler.sha256,
        "204 unit hard memory or assembler digest differs");
    let actual=singleton227_capture::properties(name,"Id,FragmentPath,DropInPaths,NeedDaemonReload,Transient,ExecStart,MemoryMax,MemorySwapMax,Restart,Type,User,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges")?;
    ensure!(actual.get("FragmentPath").is_some_and(|s|s==&b.path.to_string_lossy())
        && actual.get("DropInPaths").is_some_and(String::is_empty)
        && actual.get("NeedDaemonReload").map(String::as_str)==Some("no")
        && actual.get("Transient").map(String::as_str)==Some("no"),"204 effective unit is not this installed sealed fragment");
    for key in ["MemoryMax","MemorySwapMax","Restart","Type","User","ProtectHome","ProtectSystem","PrivateNetwork","NoNewPrivileges"] {
        ensure!(actual.get(key).map(String::as_str)==keys.get(key).copied(),"204 effective property differs: {key}");
    }
    ensure!(pipeline_status::same_exec_start(actual.get("ExecStart").context("204 command")?,
        &format!("{{ path={} ; argv[]={expected} ; ignore_errors=no }}",assembler.path.display())),
        "204 installed command differs");
    Ok(())
}
pub(super) fn admit(v:&Value,spec:&BoundFile,self_sha:&str)->Result<()> {
    let a:AdmissionSpec=serde_json::from_value(v.clone())?;
    ensure!(a.schema=="jetstreamer-epoch204-assembly-recovery-admission-spec-v1","204 admission spec");
    let p=read(&a.recovery_plan)?;custody::plan_scope(&p)?;
    let issuance=read(&a.plan_issuance)?;
    ensure!(issuance["schema"]=="jetstreamer-epoch204-assembly-recovery-plan-issuance-v1"
        && issuance["plan"]==private157::binding(&a.recovery_plan)
        && issuance["assembler"]==private157::binding(&a.assembler),"204 admission plan was not issued by the closed Rust adapter");
    let old:BoundFile=serde_json::from_value(p["original_terminal"].clone())?;custody::validate_terminal_saved(&read(&old)?)?;
    let capture=read(&serde_json::from_value(p["source_capture"].clone())?)?;
    custody::old_idle()?;custody::check_source_names(&capture)?;sealed(&a.assembler,128<<20)?;
    let current=unit(UNIT)?;ensure!(is_idle(&current) && is_idle(&unit(GUARD)?),"204 recovery owner already active or pending");
    inactive_status::no_pending_owner_trigger(UNIT,false)?;inactive_status::no_pending_owner_trigger(GUARD,false)?;
    unit_file(&a.producer_unit_file,&p,&a.recovery_plan,&a.assembler,false)?;
    unit_file(&a.guard_unit_file,&p,&a.recovery_plan,&a.assembler,true)?;
    let c=candidate(downstream::Stage::Assembly,0,minimum_disk(&p)?)?;
    let capacity=maintenance_capacity::check_assembly204_recovery(&a.resource_basis,c)?;
    validate_capacity(&capacity,c.memory_max_bytes,c.additional_bytes)?;
    custody::old_idle()?;custody::check_source_names(&capture)?;
    ensure!(unit(UNIT)?==current && is_idle(&unit(GUARD)?),"204 new owner changed across admission");
    let cap=write(&a.capacity_output,&capacity)?;
    let compact=compact_admission(&p,&a.recovery_plan,&capacity,&cap,spec,self_sha)?;
    write(Path::new(s(&p,"admission_receipt")?),&compact)?;Ok(())
}
pub(super) fn validate_capacity(v:&Value,candidate_memory:u64,additional:u64)->Result<()> {
    ensure!(v["schema"]=="jetstreamer-horizon-maintenance-capacity-v1" && v["first_epoch"]==201
        && v["last_epoch"]==300 && v["additional_bytes"]==additional
        && v["unit_census_before"]==v["unit_census_after"]
        && v["unit_census_before"]==v["unit_census_after_memory_and_guard_checks"]
        && v["all_live_growth_and_century_floor_protected"]==true
        && v["capped_peer_accounting"]["producer_and_independent_guard_hard_memory_charged"]==true
        && v["capped_peer_accounting"]["allocation_credit_bytes"]==0,"204 incomplete capacity primary evidence");
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let at=n(v,"recorded_unix_seconds")?;ensure!(at<=now && now-at<=900,"204 capacity expired");
    for phase in ["memory_before","memory_after"] {
        let m=&v[phase];let policy=&m["assembly204_recovery_memory_policy"];
        let growth=n(m,"protected_existing_memory_growth_bytes")?;
        let total=n(m,"host_total_memory_bytes")?;
        let required=total.div_ceil(10).checked_add(growth).and_then(|n|n.checked_add(candidate_memory))
            .context("204 hard memory overflow")?;
        ensure!(policy["schema"]=="jetstreamer-epoch204-assembly-recovery-hard-memory-policy-v1"
            && policy["protected_existing_hard_memory_growth_bytes"]==growth
            && policy["candidate_hard_memory_bytes"]==candidate_memory
            && policy["required_available_memory_bytes"]==required
            && m["candidate_memory_max_bytes"]==candidate_memory
            && m["minimum_available_memory_bytes"]==required
            && n(m,"sampled_available_memory_bytes")?>=required && n(m,"actual_available_memory_bytes")?>=required,
            "204 capacity understates complete hard-memory growth or candidate guard");
    }
    let disk=n(v,"minimum_free_bytes")?.checked_add(additional).context("204 disk reserve overflow")?;
    ensure!(v["required_initial_free_bytes"]==disk && n(v,"sampled_available_bytes")?>=disk
        && n(v,"actual_available_bytes")?>=disk,"204 capacity spends existing disk growth/floor");Ok(())
}
pub(super) fn compact_admission(p:&Value,plan:&BoundFile,c:&Value,cap:&BoundFile,spec:&BoundFile,self_sha:&str)->Result<Value> {
    let floor=n(c,"minimum_free_bytes")?;let memory=c["memory_before"]["candidate_memory_max_bytes"].as_u64().context("candidate memory")?;
    Ok(json!({"schema":"jetstreamer-epoch204-assembly-recovery-admission-v1","admitted":true,"epoch":204,
        "plan_sha256":plan.sha256,"executable_sha256":p["executable_sha256"],"source_capture":p["source_capture"],
        "original_terminal":p["original_terminal"],"guard_spec":p["guard_spec"],"output_root":ROOT,"unit":UNIT,"guard_unit":GUARD,
        "original_partial_preserved":true,"complete_live_claims_accounted":true,"verification_import_overlap_accounted":true,
        "zstd_level":p["zstd_level"],"maximum_output_bytes":OUTPUT_MAX,"maximum_millis":DURATION,
        "reserved_memory_bytes":memory,"incremental_disk_reserve_bytes":c["additional_bytes"],
        "sampled_unix_millis":n(c,"recorded_unix_seconds")?.checked_mul(1000).context("204 admission clock overflow")?,
        "observer_sampled_at_utc":c["sampled_at_utc"],"minimum_free_bytes":floor,"filesystem_device":fs::metadata(ROOT)?.dev(),
        "available_bytes":c["actual_available_bytes"],"live_remaining_growth_bytes":0,
        "verification_import_overlap_bytes":n(c,"additional_bytes")?.checked_sub(OUTPUT_MAX).context("204 overlap reserve")?,
        "memory_available_bytes":c["memory_before"]["actual_available_memory_bytes"],"capacity":private157::binding(cap),
        "protected_growth_included_in_minimum_free_bytes":true,"issuer":issuer(spec,self_sha),"authority":denied()}))
}
pub(super) fn validate_issued(v:&Value,plan:&BoundFile,p:&Value)->Result<()> {
    ensure!(v["schema"]=="jetstreamer-epoch204-assembly-recovery-admission-v1" && v["epoch"]==204
        && v["admitted"]==true && v["plan_sha256"]==plan.sha256 && v["source_capture"]==p["source_capture"]
        && v["original_terminal"]==p["original_terminal"] && v["guard_spec"]==p["guard_spec"]
        && v["reserved_memory_bytes"]==MEMORY+GUARD_MEMORY
        && is_lower_hex(s(&v["issuer"],"executable_sha256")?,64),"204 admission is not the closed Rust issue");
    deny(&v["authority"])?;let c=read(&serde_json::from_value(v["capacity"].clone())?)?;
    validate_capacity(&c,MEMORY+GUARD_MEMORY,OUTPUT_MAX+METADATA)?;
    ensure!(v["minimum_free_bytes"]==c["minimum_free_bytes"] && v["available_bytes"]==c["actual_available_bytes"]
        && v["memory_available_bytes"]==c["memory_before"]["actual_available_memory_bytes"]
        && n(v,"sampled_unix_millis")?==n(&c,"recorded_unix_seconds")?.checked_mul(1000).context("204 capacity time overflow")?,
        "204 compact admission does not reproduce capacity proof");Ok(())
}
pub(super) fn stage_capacity(basis:&Value,stage:downstream::Stage,bytes:u64,floor:u64)->Result<Value> {
    let c=candidate(stage,bytes,floor)?;let result=maintenance_capacity::check_assembly204_recovery(basis,c)?;
    validate_capacity(&result,c.memory_max_bytes,c.additional_bytes)?;Ok(result)
}
