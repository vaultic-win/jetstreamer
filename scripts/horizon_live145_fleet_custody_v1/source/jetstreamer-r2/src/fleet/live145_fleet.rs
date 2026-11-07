//! Exact live145 family views for fleet compatibility. Raw emitted census is retained.
use super::*;
use horizon_recovered_resource_frame_typed_bridge_v1::live145_frame as contract;
pub(super) type NativeCensus=BTreeMap<String,Value>;
pub(super) type NativeComparison=(NativeCensus,NativeCensus,Option<Value>);
pub(super) fn continuity(prior:&Value,next:&Value)->Result<()> {
 let prior_selected=contract::selected(prior)?;
 let next_selected=contract::selected(next)?;
 ensure!(!prior_selected || next_selected,"live145 protected family cannot disappear without a qualified lifecycle");
 Ok(())
}
pub(super) fn plan(raw:&Value)->Result<Value> {
 let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
 let proof=contract::capture(raw,now)?;
 ensure!(!contract::selected(raw)? || proof.is_some(),"declared live145 plan lacks actual native proof");
 contract::project_plan(raw)
}
pub(super) fn capture_native(plan:&Value,raw:&BTreeMap<String,Value>)->Result<(Option<Value>,BTreeMap<String,Value>)> {
 let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
 let proof=contract::capture(plan,now)?;
 let projected=contract::comparison_native(plan,raw,proof.as_ref())?;
 Ok((proof,projected))
}
pub(super) fn previous(plan:&Value,previous:&Value)->Result<Value> {
 let count=contract::FAMILY.iter().filter(|u|previous["unit_census"].get(**u).is_some()).count();
 if count==0{return Ok(previous.clone())}
 ensure!(count==3 && contract::selected(plan)?,"historical live145 census lost declaration or a protective role");
 let proof=contract::capture(plan,SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
 contract::comparison_fleet(plan,previous,proof.as_ref())
}
pub(super) fn compare(plan:&Value,before:&BTreeMap<String,Value>,after:&BTreeMap<String,Value>,a:&Option<Value>,b:&Option<Value>)->Result<NativeComparison> {
 let history=contract::history(a,b)?;
 Ok((contract::comparison_native(plan,before,a.as_ref())?,contract::comparison_native(plan,after,b.as_ref())?,history))
}
#[cfg(test)] mod tests {
 use super::*;
 fn p()->Value{serde_json::json!({"tracked_units":["retained.service"]})}
 fn declared()->Value{let mut p=p();p["tracked_units"].as_array_mut().unwrap().extend(contract::FAMILY.into_iter().map(|u|serde_json::json!(u)));p}
 #[test] fn old_historical_scope_stays_a_no_native_capture_comparison(){let p=p();let n=BTreeMap::from([("retained.service".into(),serde_json::json!({"Id":"retained.service"}))]);let (a,b,h)=compare(&p,&n,&n,&None,&None).unwrap();assert_eq!(a,n);assert_eq!(b,n);assert!(h.is_none());}
 #[test] fn selected_family_cannot_be_dropped_or_partially_declared(){assert!(continuity(&declared(),&p()).is_err());let mut partial=p();partial["tracked_units"].as_array_mut().unwrap().push(serde_json::json!(contract::FAMILY[0]));assert!(continuity(&p(),&partial).is_err());}
 #[test] fn a_declared_census_cannot_get_projected_without_actual_proof(){let p=declared();let n=BTreeMap::new();assert!(compare(&p,&n,&n,&None,&None).is_err());}
 #[test] fn historical_census_cannot_smuggle_an_undeclared_live_owner(){let mut old=serde_json::json!({"unit_census":{}});old["unit_census"][contract::FAMILY[0]]=serde_json::json!({"Id":contract::FAMILY[0]});assert!(previous(&p(),&old).is_err());}
}
