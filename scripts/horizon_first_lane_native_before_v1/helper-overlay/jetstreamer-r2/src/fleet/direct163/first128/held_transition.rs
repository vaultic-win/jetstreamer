//! Explicit same-sample held addition. This never creates a Frame or typed view.
//! Original accepted sources stay byte-exact; only exact new roles enter fresh raw scans.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    admission: Bound,
    enrollment: Bound,
    predecessor_fleet: Bound,
    predecessor_plan: Bound,
    successor_fleet: Bound,
    successor_plan: Bound,
    fleet_original_completion: Bound,
}
/// Private fields make this an authenticated capability, not a JSON exemption.
pub(in crate::fleet) struct Held {
    binding: Bound,
    spec: Spec,
    enrollment: Value,
    plan: Value,
    fleet: Value,
    baseline: Value,
}
impl Held {
    pub(super) fn load(binding: &Bound, enrollment: &Bound, e: &Value, admission: &Value) -> Result<Self> {
        ensure!(unsafe { libc::geteuid() } == 0
            && std::env::args().nth(1).as_deref() == Some("release-first163128"),
            "held transition is only for the actual first128 release actor");
        let spec: Spec=serde_json::from_value(immutable(binding)?)?;
        let current=&admission["memory"]["request"]["current"];
        ensure!(spec.schema=="epoch163-first128-held-enrollment-release-transition-v1"
            && json!(spec.enrollment)==json!(enrollment) && e["admission"]==json!(spec.admission)
            && immutable(&spec.admission)?==*admission
            && json!(spec.predecessor_fleet)==current["fleet"]
            && json!(spec.predecessor_plan)==current["fleet_plan"],"held transition original admission/current tuple crossed");
        let plan=immutable(&spec.successor_plan)?;
        let fleet=immutable(&spec.successor_fleet)?;
        let baseline=immutable(&spec.predecessor_fleet)?;
        let held=Self {binding:binding.clone(),spec,enrollment:e.clone(),plan,fleet,baseline};
        held.revalidate()?;
        Ok(held)
    }
    pub(in crate::fleet) fn plan(&self) -> &Value { &self.plan }
    pub(in crate::fleet) fn fleet(&self) -> &Value { &self.fleet }
    pub(in crate::fleet) fn fleet_binding(&self) -> &Bound { &self.spec.successor_fleet }
    pub(in crate::fleet) fn binding(&self) -> &Bound { &self.binding }
    pub(in crate::fleet) fn revalidate(&self) -> Result<()> {
        ensure!(immutable(&self.binding)?==self.spec_value()
            && immutable(&self.spec.enrollment)?==self.enrollment
            && immutable(&self.spec.successor_plan)?==self.plan
            && immutable(&self.spec.successor_fleet)?==self.fleet
            && immutable(&self.spec.predecessor_fleet)?==self.baseline,
            "held transition source changed");
        let p: Plan=serde_json::from_value(self.plan.clone())?;
        let sample=self.baseline["sampled_at_utc"].as_str().context("held original sample UTC")?;
        integration::validate_transition(&self.baseline,&p,&self.plan,&self.enrollment,sample,now()?)?;
        ensure!(self.fleet["schema"]=="jetstreamer-horizon-campaign-fleet-v1"
            && self.fleet["first_epoch"]==101 && self.fleet["last_epoch"]==200
            && self.plan["output"]==json!(self.spec.successor_fleet.path)
            && self.fleet["plan"]==json!(self.spec.successor_plan.path)
            && self.fleet["plan_sha256"]==self.spec.successor_plan.sha256
            && self.plan["previous_fleet"]==json!(self.spec.predecessor_fleet)
            && self.fleet["previous_fleet"]==json!(self.spec.predecessor_fleet)
            && self.plan["metadata_event"]==json!(self.spec.enrollment)
            && self.fleet["metadata_event"]==json!(self.spec.enrollment)
            && self.fleet["observer_receipt"]==self.baseline["observer_receipt"]
            && self.fleet["observer_sha256"]==self.baseline["observer_sha256"]
            && self.fleet["sampled_at_utc"]==self.baseline["sampled_at_utc"]
            && self.fleet["inventory"]["anomalies"]==0
            && self.fleet["producer_mutations"]==false && self.fleet["publication_authorized"]==false
            && self.fleet["remote_mutations"]==false,
            "held Root fleet registration is not exact same-sample enrollment");
        let completion=immutable(&self.spec.fleet_original_completion)?;
        fleet_completion(&completion,&self.spec.successor_fleet,&self.spec.successor_plan,&self.enrollment)?;
        let parent=enrollment128::native(PARENT128)?;
        let (iid,pid,ticks)=enrollment128::parent(&parent)?;
        ensure!(self.enrollment["parent_invocation_id"]==iid && self.enrollment["parent_pid"]==pid
            && self.enrollment["parent_start_ticks"]==ticks,"held parent replaced");
        enrollment128::held_owner(&self.enrollment,&parent)?;
        enrollment128::retained_protection(&self.enrollment,&parent,true)?;
        let rows=self.fleet["diagnostics"].as_array().context("held registered diagnostics")?;
        let added=rows.iter().filter(|r|r["unit"]["Id"]==PARENT128).collect::<Vec<_>>();
        ensure!(added.len()==1 && added[0]["launch_invocation_id"]==iid && added[0]["live"]==true
            && added[0]["launch_receipt"]==json!(self.spec.enrollment.path)
            && added[0]["launch_receipt_sha256"]==self.spec.enrollment.sha256,
            "held actual Root fleet lacks original diagnostic");
        Ok(())
    }
    fn spec_value(&self) -> Value {
        json!({"schema":self.spec.schema,"admission":self.spec.admission,"enrollment":self.spec.enrollment,
            "predecessor_fleet":self.spec.predecessor_fleet,"predecessor_plan":self.spec.predecessor_plan,
            "successor_fleet":self.spec.successor_fleet,"successor_plan":self.spec.successor_plan,
            "fleet_original_completion":self.spec.fleet_original_completion})
    }
    pub(in crate::fleet) fn owner(&self) -> Result<Value> {
        self.revalidate()?;
        integration::owned_owner(&self.plan)?.context("held first128 owner absent")
    }
    pub(in crate::fleet) fn allocations(&self) -> Result<Vec<Value>> {
        self.revalidate()?;
        enrollment128::allocation(&self.plan)
    }
    /// Verify the baseline Current tuple before allowing its independently
    /// authenticated held addition into the complete current raw builder.
    pub(in crate::fleet) fn require_basis(&self, fleet: &Value, plan: &Value) -> Result<()> {
        self.revalidate()?;
        ensure!(*fleet==self.baseline && *plan==immutable(&self.spec.predecessor_plan)?,
            "held raw builder cannot cross the admitted original basis");
        ensure!(integration::declared(plan)?.is_none(),"held candidate already in baseline");
        Ok(())
    }
    pub(super) fn stable_claims(&self, a:&Value, b:&Value) -> Result<()> {
        self.revalidate()?;
        let left=a["active_peer_allocations"].as_array().context("held before peers")?;
        let right=b["active_peer_allocations"].as_array().context("held after peers")?;
        ensure!(crate::fleet::recovery199::accounting::peers_equal(left,right)?,"held peer promises changed");
        let mut comparison=b.clone();
        comparison["active_peer_allocations"]=a["active_peer_allocations"].clone();
        unchanged_claims(a,&comparison)
    }
    pub(super) fn compare_raw(&self, baseline: &Value, current: &Value) -> Result<()> {
        self.revalidate()?;
        compare_claims(baseline,current,&self.enrollment,&self.spec.enrollment)
    }
}
fn fleet_completion(v: &Value, fleet: &Bound, plan: &Bound, e: &Value) -> Result<()> {
    let unit=v["unit"].as_str().context("held fleet original unit")?;
    let iid=v["invocation_id"].as_str().context("held fleet original IID")?;
    let j=&v["original_PID1_success_event"];
    let native=&v["original_native"];
    ensure!(v["schema"]=="epoch163-first128-held-fleet-original-completion-v1"
        && v["fleet"]==json!(fleet) && v["fleet_plan"]==json!(plan)
        && v["program"]==e["self"]
        && v["argv"]==json!([e["self"]["path"],"fleet-reconcile",plan.path,"--plan-sha256",plan.sha256])
        && unit.starts_with("horizon-first163128-enrollment-fleet-") && unit.ends_with(".service")
        && storage::hex(iid,32) && v["result"]=="success" && v["exec_main_status"]==0
        && v["original_outer_reaped"]==true && v["original_cgroup_empty"]==true && v["original_descriptors_drained"]==true
        && native["Id"]==unit && native["InvocationID"]==iid && native["MainPID"]=="0"
        && native["ControlPID"]=="0" && native["Job"]=="" && native["NRestarts"]=="0"
        && native["ControlGroup"]==""
        && ((native["ActiveState"]=="inactive" && native["SubState"]=="dead")
            || (native["ActiveState"]=="active" && native["SubState"]=="exited"))
        && native["Result"]=="success" && native["ExecMainStatus"]=="0"
        && j["_PID"]=="1" && j["_UID"]=="0" && j["UNIT"]==unit && j["INVOCATION_ID"]==iid
        && j["MESSAGE_ID"]=="7ad2d189f7e94e70a38c781354912448"
        && j["MESSAGE"]==format!("{unit}: Deactivated successfully."),
        "held Root fleet original completion/program/plan/drains crossed");
    let expected=vec![e["self"]["path"].as_str().context("held fleet image path")?.to_owned(),
        "fleet-reconcile".into(),plan.path.display().to_string(),"--plan-sha256".into(),plan.sha256.clone()];
    enrollment128::command(native,&expected)?;
    let recorded=j["__REALTIME_TIMESTAMP"].as_str().context("held fleet original completion time")?.parse::<u64>()?/1_000_000;
    ensure!(recorded>=n(e,"recorded_unix_seconds")? && recorded<=now()?,"held fleet original completion predates enrollment or is future");
    Ok(())
}
/// Compare claims, never rewrite or replace either original raw document.
fn compare_claims(base: &Value, raw: &Value, e: &Value, registration: &Bound) -> Result<()> {
    let iid=e["parent_invocation_id"].as_str().context("held IID")?;
    let mut comparison=raw.clone();
    for key in ["current_unique_owner_census","active_peer_allocations","projected_obligations"] {
        let original=base[key].as_array().context("held original claim table")?;
        ensure!(original.iter().all(|r|r["unit"]!=PARENT128 && r["iid"]!=iid && r["producer_invocation_id"]!=iid),"held claim already in admitted baseline");
        let rows=comparison[key].as_array_mut().context("held current claim table")?;
        if key=="current_unique_owner_census" {
            let added=rows.iter().filter(|r|r["unit"]==PARENT128).collect::<Vec<_>>();
            ensure!(added.len()==1 && *added[0]==json!({"unit":PARENT128,"iid":iid,
                "pid":e["parent_pid"],"start_ticks":e["parent_start_ticks"],"role":"diagnostic-replay",
                "first_epoch":163,"last_epoch":163,"restarts":0,"identity_stable":true,
                "guard_required":false,"has_memory_accounting":true}),"held raw owner crossed");
            rows.retain(|r|r["unit"]!=PARENT128);
        } else if key=="active_peer_allocations" {
            let added=rows.iter().filter(|r|[PARENT128,GUARD128,STOP128].iter().any(|u|r["unit"]==*u)).collect::<Vec<_>>();
            ensure!(added.len()==3 && [PARENT128,GUARD128,STOP128].iter().all(|unit|added.iter().filter(|r|r["unit"]==*unit).count()==1)
                && added.iter().all(|r|r["first163128_registration"]==json!(registration)),"held exact peer registration/census");
            for row in added.iter().filter(|r|r["unit"]!=PARENT128) {
                ensure!(row["memory_max_bytes"]==0 && row["data_reservation_bytes"]==0
                    && row["included_once_in_first128_parent_claim"]==true,"held auxiliaries duplicated memory/DATA");
            }
            let parents=added.iter().filter(|r|r["unit"]==PARENT128).collect::<Vec<_>>();
            ensure!(parents.len()==1 && parents[0]["invocation_id"]==iid && parents[0]["memory_max_bytes"]==HARD128+AUX128
                && parents[0]["data_reservation_bytes"]==768u64<<30 && parents[0]["memory_credit_bytes"]==0 && parents[0]["DATA_credit_bytes"]==0,"held full memory/DATA peer charge");
            rows.retain(|r|![PARENT128,GUARD128,STOP128].iter().any(|u|r["unit"]==*u));
        } else {
            let added=rows.iter().filter(|r|r["producer_invocation_id"]==iid).collect::<Vec<_>>();
            ensure!(added.len()==1 && added[0]["claim_key"]==format!("first163128/{iid}") && added[0]["epoch"]==163 && added[0]["outstanding_bytes"]==768u64<<30,"held exact DATA obligation");
            rows.retain(|r|r["producer_invocation_id"]!=iid);
        }
        if key=="active_peer_allocations" {
            ensure!(crate::fleet::recovery199::accounting::peers_equal(original,rows)?,"held transition changed unrelated peer promise");
            *rows=original.clone(); // authenticated comparison view only; original raw stays intact
        } else { ensure!(*rows==*original,"held transition changed unrelated {key}"); }
    }
    let hard=comparison["current_owner_hard_limits"].as_object_mut().context("held hard limits")?;
    let parent=hard.remove(PARENT128).context("held current hard parent missing")?;
    integration::raw_profile(&parent)?;
    ensure!(parent["InvocationID"]==iid && parent["MainPID"].as_str()==Some(n(e,"parent_pid")?.to_string().as_str())
        && json!(hard)==base["current_owner_hard_limits"],"held hard limits changed unrelated owner or parent");
    for (key,delta) in [("current_replay_cpu_quota_micros",10_000_000u64),("active_trial_memory_promises_bytes",HARD128+AUX128)] {
        ensure!(n(raw,key)?.checked_sub(delta)==Some(n(base,key)?),"held exact additive {key}");
        comparison[key]=base[key].clone();
    }
    // Frontiers returned by the existing raw builder are original frontiers;
    // projected obligations/guard floor own the additive DATA charge.
    for key in ["standing_frontier_bytes","confirmed_DATA_floor_bytes"] {
        ensure!(raw[key]==base[key],"held changed original DATA frontier {key}");
    }
    ensure!(n(raw,"protected_existing_DATA_bytes")?>=n(base,"protected_existing_DATA_bytes")?
        && n(raw,"inherited_live_guard_maximum_bytes")?>=n(base,"inherited_live_guard_maximum_bytes")?,"held transition reduced DATA/guard floor");
    comparison["protected_existing_DATA_bytes"]=base["protected_existing_DATA_bytes"].clone();
    unchanged_claims(base,&comparison)?;
    // Pool ownership is unchanged apart from the single finite admitted reader
    // slot becoming this actual release helper's slot. No extra pool exemption.
    let normalize_pool=|value:&Value, own:&str|->Result<Vec<Value>> {
        let mut rows=value["native_pool_suballocations"].as_array().context("held complete pool")?.clone();
        let own_rows=rows.iter().filter(|r|r["unit"]==own).collect::<Vec<_>>();
        ensure!(own_rows.len()==1 && own_rows[0]["memory_max_bytes"]==2u64<<30 && own_rows[0]["nonoverlapping_successor_slot"]==true,"held exact finite reader/release slot");
        rows.retain(|r|r["unit"]!=own);Ok(rows)
    };
    ensure!(normalize_pool(base,"horizon-failed4-current-accounting-reader-20261104-v1.service")?==normalize_pool(raw,RELEASE128)?,"held changed unrelated pool allocation");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input()->(Value,Value,Value,Bound) {
        let registration=Bound{path:REGISTER128.into(),sha256:"a".repeat(64)};
        let iid="b".repeat(32);
        let e=json!({"parent_invocation_id":iid,"parent_pid":123,"parent_start_ticks":456});
        let mut base=json!({"current_unique_owner_census":[],"active_peer_allocations":[],
            "projected_obligations":[],"current_owner_hard_limits":{},"current_replay_cpu_quota_micros":1000000,
            "active_trial_memory_promises_bytes":0,"standing_frontier_bytes":100,"confirmed_DATA_floor_bytes":100,
            "protected_existing_DATA_bytes":100,"inherited_live_guard_maximum_bytes":100,
            "native_pool_suballocations":[{"unit":"horizon-failed4-current-accounting-reader-20261104-v1.service",
                "memory_max_bytes":2u64<<30,"nonoverlapping_successor_slot":true}]});
        let mut raw=base.clone();
        raw["current_unique_owner_census"]=json!([{"unit":PARENT128,"iid":iid,"pid":123,"start_ticks":456,
            "role":"diagnostic-replay","first_epoch":163,"last_epoch":163,"restarts":0,
            "identity_stable":true,"guard_required":false,"has_memory_accounting":true}]);
        raw["active_peer_allocations"]=json!([
            {"unit":PARENT128,"invocation_id":iid,"first163128_registration":registration,"memory_max_bytes":HARD128+AUX128,"data_reservation_bytes":768u64<<30,"memory_credit_bytes":0,"DATA_credit_bytes":0},
            {"unit":GUARD128,"first163128_registration":registration,"memory_max_bytes":0,"data_reservation_bytes":0,"included_once_in_first128_parent_claim":true},
            {"unit":STOP128,"first163128_registration":registration,"memory_max_bytes":0,"data_reservation_bytes":0,"included_once_in_first128_parent_claim":true}]);
        raw["projected_obligations"]=json!([{"producer_invocation_id":iid,"claim_key":format!("first163128/{iid}"),"epoch":163,"outstanding_bytes":768u64<<30}]);
        let argv=enrollment128::parent_argv();
        raw["current_owner_hard_limits"][PARENT128]=json!({"Id":PARENT128,"LoadState":"loaded","Type":"exec","User":"sol","Group":"horizon",
            "MemoryAccounting":"yes","MemoryMax":HARD128.to_string(),"MemorySwapMax":"0","CPUQuotaPerSecUSec":"8s","TasksMax":"1024",
            "Restart":"no","NRestarts":"0","ControlGroup":format!("/system.slice/{PARENT128}"),"InvocationID":iid,"MainPID":"123",
            "ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; }}",NODE_IMAGE,argv.join(" "))});
        raw["current_replay_cpu_quota_micros"]=json!(11000000);
        raw["active_trial_memory_promises_bytes"]=json!(HARD128+AUX128);
        raw["native_pool_suballocations"][0]["unit"]=json!(RELEASE128);
        // This is a pure comparison fixture, not a Held value or runtime proof.
        base["test_only_no_runtime_authority"]=json!(true);
        (base,raw,e,registration)
    }
    #[test]
    fn exact_pure_delta_does_not_construct_a_runtime_capability() {
        let (base,raw,e,registration)=input();
        let saved=(base.clone(),raw.clone());
        compare_claims(&base,&raw,&e,&registration).unwrap();
        assert_eq!(saved,(base,raw));
    }
    #[test]
    fn omitted_duplicated_crossed_or_credited_held_claims_reject() {
        let (base,raw,e,registration)=input();
        for (pointer,value) in [
            ("/current_unique_owner_census",json!([])),
            ("/active_peer_allocations/0/first163128_registration/sha256",json!("c".repeat(64))),
            ("/active_peer_allocations/0/memory_credit_bytes",json!(1)),
            ("/active_peer_allocations/0/memory_max_bytes",json!(128u64<<30)),
            ("/projected_obligations/0/outstanding_bytes",json!(0)),
            ("/current_replay_cpu_quota_micros",json!(1000000)),
            ("/current_unique_owner_census/0/start_ticks",json!(457)),
            ("/native_pool_suballocations/0/memory_max_bytes",json!(1))] {
            let mut bad=raw.clone();*bad.pointer_mut(pointer).unwrap()=value;
            assert!(compare_claims(&base,&bad,&e,&registration).is_err(),"{pointer}");
        }
        let mut bad=raw.clone();let row=bad["active_peer_allocations"][0].clone();bad["active_peer_allocations"].as_array_mut().unwrap().push(row);
        assert!(compare_claims(&base,&bad,&e,&registration).is_err());
        let mut bad=raw;bad["projected_obligations"].as_array_mut().unwrap().push(json!({"epoch":164,"claim_key":"unrelated","producer_invocation_id":"other","outstanding_bytes":1}));
        assert!(compare_claims(&base,&bad,&e,&registration).is_err());
    }
    #[test]
    fn previous_charge_or_unrelated_owner_or_pool_change_cannot_be_projected() {
        let (base,raw,e,registration)=input();
        let mut charged=base.clone();charged["current_unique_owner_census"]=raw["current_unique_owner_census"].clone();
        assert!(compare_claims(&charged,&raw,&e,&registration).is_err());
        let mut bad=raw.clone();bad["current_owner_hard_limits"]["foreign.service"]=json!({"Id":"foreign.service"});
        assert!(compare_claims(&base,&bad,&e,&registration).is_err());
        let mut bad=raw;bad["native_pool_suballocations"].as_array_mut().unwrap().push(json!({"unit":"foreign.service","memory_max_bytes":1}));
        assert!(compare_claims(&base,&bad,&e,&registration).is_err());
    }
}
