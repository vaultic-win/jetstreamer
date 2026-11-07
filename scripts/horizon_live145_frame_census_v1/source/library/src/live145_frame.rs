//! Exact additive census adapter. Raw plans, native observations and guard tokens
//! remain in the frame; only typed comparison views remove this known family.
use super::*;
use std::collections::BTreeMap;
#[path="live145_frame/capture.rs"] mod capture;
pub const FIELD:&str="live145_prefix_guard_history";
pub const FAMILY:[&str;3]=[capture::ACTOR,capture::GUARD,capture::TIMER];
/// A plan either predates this family or appends exactly its three original roles.
/// Every other retained role and its order is left to the complete prior validator.
pub fn selected(plan:&Value)->Result<bool> {
 let rows=plan["tracked_units"].as_array().context("live145 tracked-unit array")?;
 let count=rows.iter().filter(|u|u.as_str().is_some_and(|s|FAMILY.contains(&s))).count();
 if count==0{return Ok(false)}
 ensure!(count==3 && rows.len()>=3 && rows[rows.len()-3..]==FAMILY.map(|u|json!(u)),"live145 roles must be exact nonduplicated suffix");
 Ok(true)
}
pub fn project_plan(plan:&Value)->Result<Value> {
 let mut p=plan.clone();if selected(plan)? {let rows=p["tracked_units"].as_array_mut().context("live145 tracked units")?;rows.truncate(rows.len()-3);}
 Ok(p)
}
fn strip(census:&Value)->Result<Value> {
 let mut c=census.as_object().context("live145 census object")?.clone();
 for u in FAMILY {ensure!(c.remove(u).is_some(),"live145 census family incomplete");}
 Ok(json!(c))
}
pub fn capture(plan:&Value,clock:u64)->Result<Option<Value>> {
 if !selected(plan)?{return Ok(None)}
 Ok(Some(capture::capture_now(clock)?))
}
pub fn census_view(plan:&Value,census:&Value,proof:Option<&Value>)->Result<Value> {
 if !selected(plan)? {ensure!(FAMILY.iter().all(|u|census.get(*u).is_none()),"undeclared live145 census family");return Ok(census.clone())}
 capture::check_raw(census,proof.context("live145 census lacks authenticated capture")?)?;
 strip(census)
}
pub fn project_frame(frame:&Value)->Result<Value> {
 if frame.get(FIELD).is_none(){
  ensure!(FAMILY.iter().all(|u|frame["native_census_before"].get(*u).is_none() && frame["native_census_after"].get(*u).is_none()),"live145 frame lost raw guard history");
  return Ok(frame.clone())
 }
 let h=frame[FIELD].as_array().context("live145 before/after captures")?;
 ensure!(h.len()==2,"live145 exact two captures");capture::pair(&h[0],&h[1])?;
 let mut f=frame.clone();for (k,v) in [("native_census_before",&h[0]),("native_census_after",&h[1])] {
  capture::check_raw(&frame[k],v)?;f[k]=strip(&frame[k])?;
 }
 f.as_object_mut().context("frame object")?.remove(FIELD);Ok(f)
}
pub fn history(a:&Option<Value>,b:&Option<Value>)->Result<Option<Value>> {
 match (a,b) {(None,None)=>Ok(None),(Some(a),Some(b))=>{capture::pair(a,b)?;Ok(Some(json!([a,b])))},_=>anyhow::bail!("live145 appeared/disappeared within Frame")}
}
pub struct Views {fleet:Value,plan:Value,prior_plan:Value,prior_frame:Option<Value>}
impl Views {
 pub fn prepare(e:&Evidence<'_>,proof:Option<&Value>)->Result<Option<Self>> {
  if !selected(e.fleet_plan)? {ensure!(proof.is_none(),"unselected live145 proof");return Ok(None)}
  let mut fleet=e.fleet.clone();fleet["unit_census"]=census_view(e.fleet_plan,&fleet["unit_census"],proof)?;
  Ok(Some(Self {fleet,plan:project_plan(e.fleet_plan)?,prior_plan:project_plan(e.prior_fleet_plan)?,prior_frame:e.prior_recovery.map(project_frame).transpose()?}))
 }
 pub fn evidence<'a>(&'a self,e:&'a Evidence<'_>)->Evidence<'a> {Evidence {fleet:&self.fleet,fleet_plan:&self.plan,prior_fleet_plan:&self.prior_plan,prior_recovery:self.prior_frame.as_ref(),..*e}}
}
/// Keep every existing census route after authenticating/projecting only this family.
pub fn comparison_fleet(plan:&Value,fleet:&Value,proof:Option<&Value>)->Result<Value> {
 let mut f=fleet.clone();f["unit_census"]=census_view(plan,&fleet["unit_census"],proof)?;Ok(f)
}
pub fn comparison_native(plan:&Value,native:&BTreeMap<String,Value>,proof:Option<&Value>)->Result<BTreeMap<String,Value>> {
 Ok(serde_json::from_value(census_view(plan,&json!(native),proof)?)?)
}
#[cfg(test)] mod tests {
 use super::*;
 fn plan()->Value {json!({"tracked_units":["historical.service",FAMILY[0],FAMILY[1],FAMILY[2]],"pipeline_claims":[{"retained":true}],"gates":{"145":"unready"}})}
 fn captures()->Vec<Value> {serde_json::from_str(include_str!("live145_frame/recorded-rollover-fixture.json")).unwrap()}
 fn census(v:&Value)->Value {json!({(FAMILY[0]):v["actor_native"],(FAMILY[1]):v["guard_native"],(FAMILY[2]):v["timer_native"],"historical.service":{"Id":"historical.service","unchanged":true}})}
 #[test] fn exact_additive_suffix_preserves_every_retained_policy_key() {let p=plan();let q=project_plan(&p).unwrap();assert_eq!(q["tracked_units"],json!(["historical.service"]));assert_eq!(p["pipeline_claims"],q["pipeline_claims"]);assert_eq!(p["gates"],q["gates"]);}
 #[test] fn partial_duplicate_and_reordered_family_rejected() {let p=plan();for rows in [json!(["historical.service",FAMILY[0]]),json!(["historical.service",FAMILY[0],FAMILY[1],FAMILY[1],FAMILY[2]]),json!(["historical.service",FAMILY[1],FAMILY[0],FAMILY[2]])] {let mut b=p.clone();b["tracked_units"]=rows;assert!(selected(&b).is_err());}}
 #[test] fn unknown_role_is_not_projected_as_live145() {let mut p=plan();p["tracked_units"].as_array_mut().unwrap().push(json!("foreign.service"));assert!(selected(&p).is_err());}
 #[test] fn unselected_census_cannot_smuggle_live145() {let c=census(&captures()[0]);assert!(census_view(&json!({"tracked_units":["historical.service"]}),&c,None).is_err());}
 #[test] fn selected_census_requires_independent_authenticated_proof() {assert!(census_view(&plan(),&census(&captures()[0]),None).is_err());}
 #[test] fn recorded_actual_rollover_preserves_raw_and_only_projects_exact_three() {let h=captures();assert_ne!(h[0]["guard_native"]["InvocationID"],h[1]["guard_native"]["InvocationID"]);let original=json!({"native_census_before":census(&h[0]),"native_census_after":census(&h[1]),(FIELD):h});let saved=original.clone();let f=project_frame(&original).unwrap();assert_eq!(f["native_census_before"],f["native_census_after"]);assert_eq!(original,saved);assert!(f["native_census_before"]["historical.service"]["unchanged"]==true);}
 #[test] fn actor_command_iid_restart_and_hard_limits_never_normalize() {let h=captures();for (k,v) in [("InvocationID",json!("a".repeat(32))),("ExecStart",json!("/bin/sh")),("NRestarts",json!("1")),("MemoryMax",json!("1"))] {let mut c=census(&h[0]);c[FAMILY[0]][k]=v;assert!(census_view(&plan(),&c,Some(&h[0])).is_err(),"{k}");}}
 #[test] fn failed_guard_or_changed_command_cannot_borrow_rollover() {let h=captures();for (k,v) in [("Result",json!("exit-code")),("ExecMainStatus",json!("1")),("ExecStart",json!("/bin/sh")),("NRestarts",json!("1")),("MemoryMax",json!("1")),("DropInPaths",json!("/etc/foreign.conf"))] {let mut c=census(&h[0]);c[FAMILY[1]][k]=v;assert!(census_view(&plan(),&c,Some(&h[0])).is_err(),"{k}");}}
 #[test] fn timer_iid_and_cadence_never_normalize() {let h=captures();for (k,v) in [("InvocationID",json!("a".repeat(32))),("Triggers",json!("foreign.service")),("TimersMonotonic",json!("{ OnUnitActiveUSec=60s ; next_elapse=1s }"))] {let mut b=h[1].clone();b["timer_native"][k]=v;assert!(history(&Some(h[0].clone()),&Some(b)).is_err(),"{k}");}}
 #[test] fn token_wrong_actor_floor_staleness_or_raw_bytes_rejected() {let h=captures();for (k,v) in [("actor_iid",json!("a".repeat(32))),("protected_free_bytes",json!(1)),("protected_available_memory_bytes",json!(1)),("at_boottime_millis",json!(1))] {let mut b=h[0].clone();b["token"][k]=v;assert!(census_view(&plan(),&census(&b),Some(&b)).is_err(),"{k}");}}
 #[test] fn lifecycle_appearance_disappearance_and_missing_history_rejected() {let h=captures();assert!(history(&Some(h[0].clone()),&None).is_err());assert!(project_frame(&json!({"native_census_before":census(&h[0]),"native_census_after":census(&h[1])})).is_err());}
 #[test] fn unrelated_native_change_survives_comparison_projection() {let h=captures();let a=census(&h[0]);let mut b=census(&h[1]);b["historical.service"]["unchanged"]=json!(false);assert_ne!(census_view(&plan(),&a,Some(&h[0])).unwrap(),census_view(&plan(),&b,Some(&h[1])).unwrap());}
 #[test]
 #[ignore = "Root-only readonly live145 native capture; waits for existing natural guard rollover"]
 fn actual_live145_native_capture_and_natural_guard_rollover_remain_complete() {
  let clock=||std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
  let first=capture::capture_now(clock()).unwrap();
  capture::verify_recorded(&first).unwrap();
  let before=census(&first);
  census_view(&plan(),&before,Some(&first)).unwrap();
  std::thread::sleep(std::time::Duration::from_secs(45));
  let second=capture::capture_now(clock()).unwrap();
  capture::verify_recorded(&second).unwrap();
  assert_ne!(first["guard_native"]["InvocationID"],second["guard_native"]["InvocationID"]);
  let after=census(&second);
  let original=serde_json::json!({"native_census_before":before,"native_census_after":after,(FIELD):[first,second]});
  let projected=project_frame(&original).unwrap();
  assert_eq!(projected["native_census_before"],projected["native_census_after"]);
  assert!(original.get(FIELD).is_some());
 }
}
