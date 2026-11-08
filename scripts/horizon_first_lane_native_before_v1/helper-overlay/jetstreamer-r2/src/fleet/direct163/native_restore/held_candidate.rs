//! One actual newly held native actor; no deserialized membership exemption.
use super::*;
pub(super) struct Candidate {
    spec_binding: Bound,
    spec: Value,
    issuer: Bound,
    native_plan: Bound,
    plan: Value,
    booking_binding: Bound,
    booked: Value,
    phase_binding: Bound,
    phase: Value,
    capture: Value,
}
fn bindings_shape(spec:&Value,pb:&Bound,booking:&Bound,phase:&Bound,capture:&Value)->Result<()> {
    ensure!(spec["schema"]=="epoch163-native-restore-issuer-spec-v1"
        && spec["native_plan"]==json!(pb) && spec["native_booking"]==json!(booking)
        && spec["current_phase_ledger"]==json!(phase),"native candidate original spec bindings crossed");
    let ready=&capture["ready"]["value"];
    ensure!(capture["native"]["Id"]==ACTOR && capture["native"]["InvocationID"]==capture["iid"]
        && capture["native"]["MainPID"].as_str()==Some(n(capture,"pid")?.to_string().as_str())
        && storage::hex(capture["iid"].as_str().unwrap_or(""),32) && n(capture,"pid")?>1 && n(capture,"start_ticks")?>0
        && capture["snapshot_body_opened"]==false
        && ready==&json!({"schema":"epoch163-native-input-held-v1","plan":pb,"iid":capture["iid"],"pid":capture["pid"],"snapshot_body_opened":false}),
        "native candidate actual held ready/plan/IID/PID/ticks crossed");
    Ok(())
}
impl Candidate {
    /// Only native_restore::run supplies its already-authenticated initial
    /// held::capture. Every use reopens the exact spec/plan/booking/phase and
    /// recaptures the sole real held actor with ready/namespace/mapped image.
    pub(super) fn load(sb:&Bound,issuer:&Bound,s:&NativeSpec,p:&NativePlan,first:&Value)->Result<Self> {
        let spec=immutable(sb)?;
        bindings_shape(&spec,&s.native_plan,&s.native_booking,&s.current_phase_ledger,first)?;
        let plan_value=immutable(&s.native_plan)?;
        ensure!(plan_value==serde_json::to_value(p)?,"native candidate original plan crossed");
        let candidate=Self {spec_binding:sb.clone(),spec,issuer:issuer.clone(),native_plan:s.native_plan.clone(),plan:plan_value,
            booking_binding:s.native_booking.clone(),booked:booking(s)?,phase_binding:s.current_phase_ledger.clone(),
            phase:provenance::phases(s)?,capture:first.clone()};
        candidate.revalidate()?;
        Ok(candidate)
    }
    pub(super) fn revalidate(&self)->Result<()> {
        ensure!(env::args().nth(1).as_deref()==Some("admit-native163")
            && self_actor(&self.spec_binding,&self.issuer.sha256)?==self.issuer
            && immutable(&self.spec_binding)?==self.spec,"native candidate actual issuer/spec changed");
        let s:NativeSpec=serde_json::from_value(self.spec.clone())?;
        bindings_shape(&self.spec,&self.native_plan,&self.booking_binding,&self.phase_binding,&self.capture)?;
        ensure!(same(&s.native_plan,&self.native_plan) && same(&s.native_booking,&self.booking_binding)
            && same(&s.current_phase_ledger,&self.phase_binding),"native candidate exact plan/booking/phase crossed");
        let p=plan(&self.native_plan,&self.issuer)?;
        ensure!(serde_json::to_value(&p)?==self.plan && booking(&s)?==self.booked
            && provenance::phases(&s)?==self.phase,"native candidate plan/booking/phase changed");
        prepared_phase_fit(&p,&self.phase)?;
        ensure!(held::capture(&p,&self.native_plan)?==self.capture,"native candidate actual held identity/ready/namespace changed");
        Ok(())
    }
    pub(super) fn capture(&self)->&Value { &self.capture }
    pub(super) fn require_original_absent(&self,raw:&Value)->Result<()> {
        for field in ["native_before","native_after","workload_discovery_before","workload_discovery_after"] {
            let rows=raw[field].as_object().with_context(||format!("native candidate original {field} missing"))?;
            ensure!(!rows.contains_key(ACTOR),"native candidate already existed in original reader {field}: {ACTOR}");
        }
        Ok(())
    }
    pub(super) fn evidence(&self)->Value {
        json!({"schema":"epoch163-native-original-held-candidate-induction-v1","issuer_spec":self.spec_binding,
            "native_plan":self.native_plan,"native_booking":self.booking_binding,"current_phase_ledger":self.phase_binding,
            "actor_unit":ACTOR,"actor_invocation_id":self.capture["iid"],"actor_pid":self.capture["pid"],
            "actor_start_ticks":self.capture["start_ticks"],"ready":self.capture["ready"],
            "comparison_only":true,"memory_bytes_still_charged":MEMORY,"candidate_DATA_bytes_still_charged":SCRATCH,
            "memory_credit_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_spec_plan_booking_phase_and_actual_ready_cannot_cross() {
        let bound=|name:&str|Bound{path:format!("/genuine/{name}.json").into(),sha256:"a".repeat(64)};
        let (plan,booking,phase)=(bound("plan"),bound("booking"),bound("phase"));
        let spec=json!({"schema":"epoch163-native-restore-issuer-spec-v1","native_plan":plan,"native_booking":booking,"current_phase_ledger":phase});
        let iid="b".repeat(32);
        let capture=json!({"iid":iid,"pid":222,"start_ticks":333,"snapshot_body_opened":false,
            "native":{"Id":ACTOR,"InvocationID":iid,"MainPID":"222"},
            "ready":{"value":{"schema":"epoch163-native-input-held-v1","plan":plan,"iid":iid,"pid":222,"snapshot_body_opened":false}}});
        bindings_shape(&spec,&plan,&booking,&phase,&capture).unwrap();
        // Pure shape validation cannot construct the private actual Candidate.
        for key in ["native_plan","native_booking","current_phase_ledger"] {
            let mut crossed=spec.clone();crossed[key]=json!(bound("foreign"));
            assert!(bindings_shape(&crossed,&plan,&booking,&phase,&capture).is_err(),"{key}");
        }
        for key in ["plan","iid","pid","snapshot_body_opened"] {
            let mut crossed=capture.clone();crossed["ready"]["value"][key]=json!("crossed");
            assert!(bindings_shape(&spec,&plan,&booking,&phase,&crossed).is_err(),"ready {key}");
        }
        for key in ["iid","pid","start_ticks","snapshot_body_opened"] {
            let mut crossed=capture.clone();crossed[key]=json!(0);
            assert!(bindings_shape(&spec,&plan,&booking,&phase,&crossed).is_err(),"capture {key}");
        }
    }
}
