//! Pure validation of the completed167 accounting evidence; no native sampling.
use anyhow::{ensure, Result};
use serde_json::Value;
pub const RETAINED_CAP: u64 = 128 << 20;
pub const OLD_CAP: u64 = 5 << 30;
pub const REVIEW_PATH: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/scratch167-completed-output-scope-review-v1/sealed/REVIEW.json";
pub const REVIEW_SHA: &str = "ccd816b11dc91d40d5aa8cd78c15325051d605cd9d699585a87cae692315440f";
pub fn validate_report(v: &Value, full_hash: bool) -> Result<()> {
 ensure!(v.as_object().is_some_and(|m|m.len()==12)
  && v["schema"]=="horizon-completed-scratch167-output-scope-validation-v1"
  && v["review"]==serde_json::json!({"path":REVIEW_PATH,"sha256":REVIEW_SHA})
  && v["retained_physical_bytes"]==127434752u64
  && v["retained_capacity_bytes"]==RETAINED_CAP
  && v["original_allowance_bytes"]==OLD_CAP
  && v["potential_allowance_reduction_bytes"]==OLD_CAP-RETAINED_CAP
  && v["full_file_hashes_checked"]==full_hash
  && v["existing_guards_changed"]==false && v["booking_changed"]==false
  && v["resource_credit_bytes"]==0 && v["replay_admission_authorized"]==false,
  "exact completed167 output accounting evidence required");
 let rows=v["native"].as_array().filter(|r|r.len()==2).ok_or_else(||anyhow::anyhow!("exact two completed writers"))?;
 for (r, phase) in rows.iter().zip(["check","execute"]) {
  ensure!(r.as_object().is_some_and(|m|m.len()==14)
   && r["Id"]==format!("horizon-retry3-scratch167-retire-167-{phase}-20261115-v2.service")
   && r["LoadState"]=="not-found" && r["ActiveState"]=="inactive" && r["SubState"]=="dead"
   && r["MainPID"]=="0" && r["ControlPID"]=="0" && r["NRestarts"]=="0", "completed writer absent");
  for k in ["Job","Triggers","TriggeredBy","OnSuccess","OnFailure","FragmentPath","InvocationID"] {
   ensure!(r[k]=="", "completed writer has replacement, job, or definition");
  }
 }
 Ok(())
}
#[cfg(test)]
mod tests {
 use super::*;
 use serde_json::json;
 fn report()->Value {
  let native:Vec<Value>=["check","execute"].into_iter().map(|phase|json!({
   "Id":format!("horizon-retry3-scratch167-retire-167-{phase}-20261115-v2.service"),
   "LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0",
   "Job":"","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":"","FragmentPath":"","InvocationID":""})).collect();
  json!({"schema":"horizon-completed-scratch167-output-scope-validation-v1","review":{"path":REVIEW_PATH,"sha256":REVIEW_SHA},
   "retained_physical_bytes":127434752u64,"retained_capacity_bytes":RETAINED_CAP,"original_allowance_bytes":OLD_CAP,
   "potential_allowance_reduction_bytes":OLD_CAP-RETAINED_CAP,"full_file_hashes_checked":true,"native":native,
   "existing_guards_changed":false,"booking_changed":false,"resource_credit_bytes":0,"replay_admission_authorized":false})
 }
 #[test] fn exact_report_and_distinct_hash_modes() {
  let mut r=report();validate_report(&r,true).unwrap();assert!(validate_report(&r,false).is_err());
  r["full_file_hashes_checked"]=json!(false);validate_report(&r,false).unwrap();assert!(validate_report(&r,true).is_err());
 }
 #[test] fn altered_budget_proof_and_authority_rejected() {
  for (k,x) in [("retained_capacity_bytes",json!(OLD_CAP)),("original_allowance_bytes",json!(0)),("potential_allowance_reduction_bytes",json!(OLD_CAP)),("resource_credit_bytes",json!(1)),("booking_changed",json!(true)),("replay_admission_authorized",json!(true)),("retained_physical_bytes",json!(127434751u64)),("review",json!({}))] {
   let mut r=report();r[k]=x;assert!(validate_report(&r,true).is_err(),"{k}");
  }
  let mut r=report();r["extra"]=json!(0);assert!(validate_report(&r,true).is_err());
 }
 #[test] fn replacement_writer_and_incomplete_census_rejected() {
  for k in ["Id","InvocationID","Job","OnSuccess","OnFailure","LoadState","MainPID","FragmentPath"] {
   let mut r=report();r["native"][0][k]=json!("changed");assert!(validate_report(&r,true).is_err(),"{k}");
  }
  let mut r=report();r["native"].as_array_mut().unwrap().pop();assert!(validate_report(&r,true).is_err());
 }
}
