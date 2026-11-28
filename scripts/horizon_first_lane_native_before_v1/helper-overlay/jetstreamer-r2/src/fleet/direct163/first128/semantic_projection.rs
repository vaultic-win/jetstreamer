//! Exact original reader retention semantics on each fresh complete first128 scan.
//! A private constructor requires the genuine opaque view; no caller row or credit.
use super::*;
type RetentionPlan=crate::fleet::charge136_retry0005::contract::Plan;
type Retained=crate::fleet::charge136_retry0005::retained_attempt::RetainedAttempt;
pub(super) struct Projection {reader:Bound,proof:Value,spec:Value,request:Value,retention_binding:Bound,retention:RetentionPlan,retained:Retained}
fn lineage(proof:&Value,spec:&Value,request:&Value,sources:&Value)->Result<()> {
 ensure!(proof["schema"]=="failed4-current-complete-accounting-reader-proof-v1"
  && proof["image"]==request["reader_program"]["program"]
  && proof["retention_plan"]==spec["retention_plan"] && proof["external_booking"]==spec["external_booking"]
  && spec["resource_accounting"]==*sources && sources["observer"]==request["current"]["observer"]
  && sources["fleet"]==request["current"]["fleet"] && sources["fleet_plan"]==request["current"]["fleet_plan"]
  && sources["phase_events"][1]["source"]==request["current"]["frame"],"first128 original retention/source/image tuple crossed");
 Ok(())
}
impl Projection {
 pub(super) fn load(request:&memory::model::Request,view:&memory::VerifiedParentMemory,sources:&Value,clock:u64)->Result<Self>{
  ensure!(matches!(env::args().nth(1).as_deref(),Some("admit-first163128"|"release-first163128"))
   && view.evidence()["request"]==json!(request),"first128 semantic projection requires actual role and genuine opaque request");
  let reader=to_bound(&json!(request.current_reader))?;let proof=immutable(&reader)?;
  let at=n(&proof,"recorded_unix_seconds")?;ensure!(at<=clock && clock-at<=300,"first128 original reader projection freshness");
  let spec=immutable(&to_bound(&proof["spec"])?)?;lineage(&proof,&spec,&json!(request),sources)?;
  let retention_binding=to_bound(&proof["retention_plan"])?;
  let retention:RetentionPlan=serde_json::from_value(immutable(&retention_binding)?)?;
  let retained=crate::fleet::charge136_retry0005::retained_attempt::actual(&retention)?;
  for (raw,projected) in [("original_raw_builder_before","accounting_before"),("original_raw_builder_after","accounting")] {
   let original=immutable(&to_bound(&proof[raw])?)?;
   let semantic=crate::fleet::charge136_retry0005::retained_attempt::project(&retention,&original,&retained)?;
   ensure!(semantic==immutable(&to_bound(&proof[projected])?)?,"first128 exact original retention projection differs");
  }
  Ok(Self{reader,proof,spec,request:json!(request),retention_binding,retention,retained})
 }
 pub(super) fn project(&self,raw:&Value)->Result<Value>{
  ensure!(immutable(&self.reader)?==self.proof && immutable(&to_bound(&self.proof["spec"])?)?==self.spec
   && immutable(&self.retention_binding)?==serde_json::to_value(&self.retention)?
   && crate::fleet::charge136_retry0005::retained_attempt::actual(&self.retention)?==self.retained,"first128 original semantic projection custody changed");
  for key in ["observer","fleet"] {ensure!(raw[key]==self.request["current"][key],"first128 fresh semantic tuple crossed: {key}");}
  // The qualified projector preserves the whole raw report and can only conserve
  // missing retained RAM/DATA/CPU obligations. It rejects re-projection/credit.
  crate::fleet::charge136_retry0005::retained_attempt::project(&self.retention,raw,&self.retained)
 }
 pub(super) fn revalidate(&self,request:&memory::model::Request,view:&memory::VerifiedParentMemory,sources:&Value,clock:u64)->Result<()> {
  let current=Self::load(request,view,sources,clock)?;
  ensure!(json!(current.reader)==json!(self.reader) && current.proof==self.proof && current.request==self.request
   && current.retained==self.retained && json!(current.retention_binding)==json!(self.retention_binding),"first128 final semantic source changed");Ok(())
 }
 pub(super) fn evidence(&self)->Value{json!({"schema":"epoch163-first128-exact-original-retention-projection-v1","reader":self.reader,"retention_plan":self.retention_binding,"original_raw_reports_preserved":true,"no_helper_or_native_census_normalization":true,"memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0})}
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn original_projection_lineage_rejects_crossed_image_retention_booking_and_tuple(){
 let sources=json!({"observer":{"path":"/observer"},"fleet":{"path":"/fleet"},"fleet_plan":{"path":"/plan"},"phase_events":[{}, {"source":{"path":"/frame"}}]});
 let request=json!({"reader_program":{"program":{"path":"/reader"}},"current":{"observer":sources["observer"],"fleet":sources["fleet"],"fleet_plan":sources["fleet_plan"],"frame":{"path":"/frame"}}});
 let proof=json!({"schema":"failed4-current-complete-accounting-reader-proof-v1","image":request["reader_program"]["program"],"retention_plan":{"path":"/retention"},"external_booking":{"path":"/booking"}});
 let spec=json!({"retention_plan":proof["retention_plan"],"external_booking":proof["external_booking"],"resource_accounting":sources});
 lineage(&proof,&spec,&request,&sources).unwrap();
 for field in ["image","retention_plan","external_booking"] {let mut changed=proof.clone();changed[field]=json!({"path":"/foreign"});assert!(lineage(&changed,&spec,&request,&sources).is_err(),"{field}");}
 for field in ["observer","fleet","fleet_plan"] {let mut changed=sources.clone();changed[field]=json!({"path":"/foreign"});assert!(lineage(&proof,&spec,&request,&changed).is_err(),"{field}");}
 let mut changed=request;changed["current"]["frame"]=json!({"path":"/foreign"});assert!(lineage(&proof,&spec,&changed,&sources).is_err());
 }
}
