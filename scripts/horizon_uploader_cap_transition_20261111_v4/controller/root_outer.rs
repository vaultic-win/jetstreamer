//! The separate Root control allocation never aliases the disposable aggregate.
use super::*;
pub(super) fn validate_root_outer_shape(outer: &RootOuter) -> Result<()> {
    ensure!(outer.unit.ends_with(".service") && outer.unit.len()<=240 && outer.unit.bytes().all(|b|b.is_ascii_alphanumeric() || b"._-".contains(&b)),"invalid Root outer unit");
    ensure!(outer.unit!=OWN_UNIT && outer.unit!=UNIT && !outer.unit.starts_with("horizon-uploader-cap-transition-reader-"),"Root outer aliases a fixture actor");
    ensure!(outer.invocation_id.len()==32 && outer.invocation_id.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) && outer.main_pid>1 && outer.start_ticks>0,"invalid exact Root outer identity");
    let cg=Path::new(&outer.control_group);
    let aggregate=PathBuf::from(format!("/{SLICE}"));
    ensure!(cg.is_absolute() && cg!=Path::new("/") && outer.control_group.len()<=1024 && !outer.control_group.contains("//") && cg.components().all(|c|matches!(c,std::path::Component::RootDir|std::path::Component::Normal(_))),"noncanonical Root outer cgroup");
    ensure!(!cg.starts_with(&aggregate) && !aggregate.starts_with(cg),"Root outer and fixture aggregate must be disjoint, charged allocations");
    Ok(())
}
pub(super) fn validate_transition_booking(booking: &Value, outer: &RootOuter) -> Result<()> {
    validate_root_outer_shape(outer)?;
    let others=booking["other_retained_native16_committed_bytes"].as_u64().context("all other retained native16 commitments required")?;
    let total=(2u64<<30).checked_add(others).context("native16 commitment overflow")?;
    ensure!(booking["schema"]=="horizon-isolated-cap-transition-retained-booking-v2" && booking["owner"]=="/root"
        && booking["retained_native16_bytes"]==(16u64<<30)
        && booking["aggregate_controller_fixture_reader_bytes"]==SHARED
        && booking["fixture_aggregate_slice_bytes"]==SHARED
        && booking["root_outer_bytes"]==SHARED
        && booking["total_transition_and_root_outer_bytes"]==(2u64<<30)
        && booking["root_outer_identity"]==serde_json::to_value(outer)?
        && booking["root_outer_allocation_is_disjoint"]==true
        && booking["all_other_retained_native16_commitments_preserved"]==true
        && booking["native16_total_with_transition_bytes"]==total && total<=16u64<<30
        && booking["compiler_active_during_capture"]==false
        && booking["existing_OS_source_artifact_bytes"]==(512u64<<20)
        && booking["OS_floor_bytes"]==(64u64<<30)
        && booking["all_memory_promises_retained_bytes"]==759789531136u64
        && booking["all_DATA_promises_retained_bytes"]==6229838610226u64
        && booking["new_resource_promise_bytes"]==0 && booking["resource_credit_bytes"]==0,
        "separate Root outer plus fixture aggregate not exactly funded inside retained native16");
    Ok(())
}
pub(super) fn root_outer_envelope(p: &Plan, r: &mut Runner, prepare_stage: bool) -> Result<Value> {
    let outer=&p.root_outer;
    validate_transition_booking(&json_bound(&p.bindings.booking)?,outer)?;
    let keys="Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ControlGroup,MemoryMax,MemorySwapMax,MemoryAccounting,Restart,User,Group,Job";
    let expected_pid=outer.main_pid.to_string();
    let expected_shared=SHARED.to_string();
    let before=r.show(&outer.unit,keys)?;
    ensure!(before["Id"]==outer.unit && before["LoadState"]=="loaded" && before["ActiveState"]=="active" && before["SubState"]=="running" && before["InvocationID"]==outer.invocation_id && before["MainPID"]==expected_pid
        && before["ControlPID"]=="0" && before["NRestarts"]=="0" && before["ControlGroup"]==outer.control_group && before["MemoryMax"]==expected_shared && before["MemorySwapMax"]=="0" && before["MemoryAccounting"]=="yes" && before["Restart"]=="no" && before["User"]=="root" && before["Group"]=="root" && before["Job"]=="", "separate Root outer native identity/envelope differs");
    ensure!(start_ticks(outer.main_pid)?==outer.start_ticks,"Root outer process birth changed");
    let c=Path::new("/sys/fs/cgroup").join(outer.control_group.trim_start_matches('/'));
    ensure!(c.canonicalize()?==c,"Root outer kernel path escape");
    ensure!(String::from_utf8(bounded(&c.join("memory.max"),64)?)?.trim()==SHARED.to_string() && String::from_utf8(bounded(&c.join("memory.swap.max"),64)?)?.trim()=="0","Root outer kernel hard limits differ");
    let members=String::from_utf8(bounded(&c.join("cgroup.procs"),65536)?)?;
    ensure!(members.split_whitespace().any(|s|s==outer.main_pid.to_string()),"Root outer main process absent from booked cgroup");
    let process_cg=String::from_utf8(bounded(&PathBuf::from(format!("/proc/{}/cgroup",outer.main_pid)),65536)?)?;
    ensure!(process_cg.trim()==format!("0::{}",outer.control_group),"Root outer proc scope differs");
    if prepare_stage {
        let own=String::from_utf8(bounded(Path::new("/proc/self/cgroup"),65536)?)?;
        let path=own.trim().strip_prefix("0::").context("prepare unified cgroup")?;
        ensure!(Path::new(path).starts_with(Path::new(&outer.control_group)),"prepare must be funded by separate Root outer, outside absent fixture aggregate");
    }
    let after=r.show(&outer.unit,keys)?;
    ensure!(before==after && start_ticks(outer.main_pid)?==outer.start_ticks,"Root outer changed during native validation");
    Ok(json!({"root_outer":outer,"native":after,"root_outer_bytes":SHARED,"fixture_aggregate_bytes":SHARED,"total_transition_and_root_outer_bytes":2u64<<30,"disjoint_allocations":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn outer() -> RootOuter {RootOuter{unit:"root-retained-control.service".into(),invocation_id:"a".repeat(32),main_pid:42,start_ticks:84,control_group:"/system.slice/root-retained-control.service".into()}}
    fn booking(outer: &RootOuter) -> Value {
        json!({"schema":"horizon-isolated-cap-transition-retained-booking-v2","owner":"/root","retained_native16_bytes":16u64<<30,"aggregate_controller_fixture_reader_bytes":SHARED,"fixture_aggregate_slice_bytes":SHARED,"root_outer_bytes":SHARED,"total_transition_and_root_outer_bytes":2u64<<30,"root_outer_identity":outer,"root_outer_allocation_is_disjoint":true,"all_other_retained_native16_commitments_preserved":true,"other_retained_native16_committed_bytes":8u64<<30,"native16_total_with_transition_bytes":10u64<<30,"compiler_active_during_capture":false,"existing_OS_source_artifact_bytes":512u64<<20,"OS_floor_bytes":64u64<<30,"all_memory_promises_retained_bytes":759789531136u64,"all_DATA_promises_retained_bytes":6229838610226u64,"new_resource_promise_bytes":0,"resource_credit_bytes":0})
    }
    #[test]
    fn root_outer_cannot_alias_or_contain_fixture_aggregate() {
        let mut r=outer();validate_root_outer_shape(&r).unwrap();
        for c in [format!("/{SLICE}"),format!("/{SLICE}/nested.service"),"/".into(),"/system.slice/../escape.service".into()] {r.control_group=c;assert!(validate_root_outer_shape(&r).is_err());}
    }
    #[test]
    fn both_disjoint_gibibytes_and_all_retained_native16_rows_are_required() {
        let r=outer();let good=booking(&r);validate_transition_booking(&good,&r).unwrap();
        for (key,value) in [("root_outer_bytes",json!(0)),("total_transition_and_root_outer_bytes",json!(SHARED)),("root_outer_allocation_is_disjoint",json!(false)),("all_other_retained_native16_commitments_preserved",json!(false))] {
            let mut b=good.clone();b[key]=value;assert!(validate_transition_booking(&b,&r).is_err());
        }
        let mut b=good.clone();b["other_retained_native16_committed_bytes"]=json!(15u64<<30);b["native16_total_with_transition_bytes"]=json!(17u64<<30);assert!(validate_transition_booking(&b,&r).is_err());
        let mut b=good;b["root_outer_identity"]["main_pid"]=json!(43);assert!(validate_transition_booking(&b,&r).is_err());
    }
}
