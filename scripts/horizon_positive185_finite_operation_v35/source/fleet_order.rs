use crate::*;
pub const SUFFIX:[&str;7]=["horizon-qualify-145-cached-b2a09f57de39c384.service","horizon-qualify-145-cached-b2a09f57de39c384-guard.service","horizon-qualify-145-cached-b2a09f57de39c384-guard.timer","horizon-qualify-145-cached-b2a09f57de39c384-stop.service","horizon-extract145-prefix-shared72h-20261107-v8g1.service","horizon-guard145-prefix-shared72h-20261107-v8g1.service","horizon-guard145-prefix-shared72h-20261107-v8g1.timer"];
pub fn insert(plan:&mut Value,event:&Value)->Result<()> {
 let rows=plan["tracked_units"].as_array().context("tracked-unit array")?;
 ensure!(rows.len()>=SUFFIX.len() && rows[rows.len()-SUFFIX.len()..].iter().zip(SUFFIX).all(|(v,s)|v==s),"exact retained cached/live145 suffix required");
 for name in SUFFIX {ensure!(rows.iter().filter(|v|v.as_str()==Some(name)).count()==1,"retained145 suffix role duplicated");}
 let mut additions=Vec::new();
 for key in ["actor_unit","guard_unit","timer_unit"] {let name=text(event,key)?;ensure!(unit_name(name) && !rows.iter().any(|v|v==name) && !additions.iter().any(|v|v==name),"cold185 role duplicate or malformed");additions.push(json!(name));}
 let at=rows.len()-SUFFIX.len();let mut candidate=plan.clone();candidate["tracked_units"].as_array_mut().unwrap().splice(at..at,additions);
 ensure!(horizon_live145_contract::live145_frame::selected(&candidate)?,"actual Helper32 live145 consumer contract required");
 let projected=horizon_live145_contract::live145_frame::project_plan(&candidate)?;
 ensure!(projected["tracked_units"].as_array().context("projected roles")?.ends_with(&SUFFIX[..4].iter().map(|s|json!(s)).collect::<Vec<_>>()),"cached145 suffix preserved after live145 projection");
 *plan=candidate;Ok(())
}
#[cfg(test)]mod tests {
 use super::*;
 fn event()->Value {json!({"actor_unit":"horizon-qualify-185-test.service","guard_unit":"horizon-guard-185-test.service","timer_unit":"horizon-guard-185-test.timer"})}
 fn plan()->Value {let mut rows=vec![json!("unrelated-first.service"),json!("unrelated-second.service")];rows.extend(SUFFIX.map(|s|json!(s)));json!({"tracked_units":rows,"other":{"exact":"preserved"}})}
 #[test]fn actual_consumer_accepts_insert_before_both_retained_families(){let mut p=plan();let before=p.clone();insert(&mut p,&event()).unwrap();let rows=p["tracked_units"].as_array().unwrap();assert_eq!(&rows[..2],&before["tracked_units"].as_array().unwrap()[..2]);assert_eq!(&rows[5..],&before["tracked_units"].as_array().unwrap()[2..]);assert_eq!(p["other"],before["other"]);assert!(horizon_live145_contract::live145_frame::selected(&p).unwrap());}
 #[test]fn missing_reordered_and_duplicated_suffix_reject_without_edit(){for kind in 0..3{let mut p=plan();let rows=p["tracked_units"].as_array_mut().unwrap();match kind{0=>{rows.pop();},1=>rows.swap(2,3),_=>rows.insert(0,json!(SUFFIX[0]))};let before=p.clone();assert!(insert(&mut p,&event()).is_err());assert_eq!(p,before);}}
 #[test]fn duplicate_new_roles_and_second_enrollment_reject_without_edit(){let mut p=plan();insert(&mut p,&event()).unwrap();let before=p.clone();assert!(insert(&mut p,&event()).is_err());assert_eq!(p,before);let mut e=event();e["guard_unit"]=e["actor_unit"].clone();let mut p=plan();let before=p.clone();assert!(insert(&mut p,&e).is_err());assert_eq!(p,before);}
 #[test]#[ignore="Root actual sealed21:00 failed plan through same Helper32 consumer; metadata only"]
 fn actual_original2100_failed_plan_repairs_without_dropping_any_role(){let f=Path::new("/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-fleet-32daf31d08974cda8b3d302030fbf3cc/spec.json");let raw=storage::bytes(&fixed(f.to_str().unwrap(),"f7f5dfc7ca22d7b1d99756402f47e2a516eb21aaaba6d712dee7ba650a065bad"),4<<20,true).unwrap();let mut p:Value=serde_json::from_slice(&raw).unwrap();assert!(horizon_live145_contract::live145_frame::selected(&p).is_err());let original=p["tracked_units"].as_array().unwrap().clone();let len=original.len();let e=json!({"actor_unit":original[len-3],"guard_unit":original[len-2],"timer_unit":original[len-1]});p["tracked_units"].as_array_mut().unwrap().truncate(len-3);insert(&mut p,&e).unwrap();assert!(horizon_live145_contract::live145_frame::selected(&p).unwrap());let rows=p["tracked_units"].as_array().unwrap();assert_eq!(rows.len(),original.len());let mut a=rows.clone();let mut b=original.clone();a.sort_by_key(|v|v.to_string());b.sort_by_key(|v|v.to_string());assert_eq!(a,b);}
}
