//! Separate held-worker release after full current fleet and actual armed guard.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSpec {
    schema: String,
    enrollment: Bound,
    runtime_plan: Bound,
    current_phase_ledger: Bound,
    memory_request: memory::model::Request,
    data_policy: Bound,
    data_policy_seal: Bound,
    resource_accounting: Value,
}
pub(super) async fn run() -> Result<()> {
    let (sb, image)=actor128("release-first163128", RELEASE128)?;
    let s:ReleaseSpec=serde_json::from_value(immutable(&sb)?)?;
    ensure!(s.schema=="epoch163-first-output128-held-release-spec-v1" && s.enrollment.path==Path::new(REGISTER128),"first128 release exact registration");
    let e=immutable(&s.enrollment)?;
    let a=&e["admission_value"];
    ensure!(e["self"]==json!(image),"first128 cohesive admission/enrollment/release issuer");
    let plan=immutable(&s.runtime_plan)?;
    ensure!(plan["schema"]=="epoch163-first-output128-private-plan-v1"
        && plan["admission"]==e["admission"] && plan["input_policy"]==e["input_policy"],"first128 exact released runtime plan");
    let phase=current_phase::validate(&s.current_phase_ledger)?;
    let admission_spec:BoundedSpec=serde_json::from_value(immutable(&to_bound(&a["spec"])?)?)?;
    let input_policy=immutable(&admission_spec.input_policy)?;
    let input_bound=to_bound(&input_policy["input_acceptance"])?;
    let inputs=immutable(&input_bound)?;
    let native_retained=native_capability::validate(&input_bound,&inputs,&admission_spec.native_finalizer_completion)?;
    let view=memory::admission_bridge::from_current_reader(&s.memory_request,now()?)?;
    let selected=data::select(&view,&s.data_policy,&s.data_policy_seal,now()?)?;
    ensure!(view.selected_parent_retirement_bytes()==192u64<<30 && view.selected_cached145_parent_retirement_bytes()==192u64<<30, "first128 release preserves both typed retirement selections");
    let current=&view.evidence()["request"]["current"];
    ensure!(s.resource_accounting["observer"]==current["observer"]
        && s.resource_accounting["fleet"]==current["fleet"]
        && s.resource_accounting["fleet_plan"]==current["fleet_plan"]
        && s.resource_accounting["phase_events"][1]["source"]==current["frame"],"first128 release complete current tuple");
    let fleet_plan=protected(&to_bound(&current["fleet_plan"])?)?;
    ensure!(integration::declared(&fleet_plan)?.is_some_and(|b|json!(b)==json!(s.enrollment)),"first128 release requires actual enrolled current fleet");
    let before=epoch186::accounting::protected_data_basis(&s.resource_accounting,now()?).await?;
    let p0=physical()?;
    let after=epoch186::accounting::protected_data_basis(&s.resource_accounting,now()?).await?;
    let p1=physical()?;
    epoch186::accounting::stable_guard_basis(&s.resource_accounting,&before,&after)?;
    unchanged_claims(&before,&after)?;
    let budget=candidate_memory128::compose(&view,&selected,&phase,&native_retained,
        &before,&after,candidate_memory128::Stage::Enrolled(&s.enrollment))?;
    let floor=budget.required_free_bytes().max(n(a,"minimum_free_bytes")?);
    // Enrollment owns its exact existing replay charge. Retained native128 is
    // still added independently; release adds no second replay claim or credit.
    for p in [&p0,&p1] {
        ensure!(n(p,"free_bytes")? >= floor
            && n(p,"available_memory_bytes")? >= EXPORT128+HARD128+AUX128+MARGIN128
            && n(p,"free_inodes")? >= 131072 && n(p,"vm_max_map_count")? >= 4194304,
            "first128 release fresh complete physical/DATA/VMA floor");
    }
    let observer=storage::json(&to_bound(&current["observer"])?)?;
    let host=n(&observer["host_memory"],"total_kib")?.checked_mul(1024).context("release host overflow")?;
    budget.host_fit(host)?;
    fits(budget.evidence(),floor.checked_sub(768u64<<30).context("release floor lacks candidate DATA")?,host,&p0,&p1)?;
    let cpu=n(&after,"current_replay_cpu_quota_micros")?.checked_add(1_000_000).context("release CPU overflow")?;
    ensure!(n(&p0,"available_logical_cpus")?==n(&p1,"available_logical_cpus")?
        && n(&p1,"available_logical_cpus")?.checked_mul(1_000_000).is_some_and(|capacity|cpu<=capacity),"first128 current release CPU capacity");
    let parent=enrollment128::native(PARENT128)?;
    let (iid,pid,ticks)=enrollment128::parent(&parent)?;
    ensure!(e["parent_invocation_id"]==iid && e["parent_pid"]==pid && e["parent_start_ticks"]==ticks,"first128 held owner changed before release");
    enrollment128::held_owner(&e,&parent)?;
    enrollment128::retained_protection(&e,&parent,true)?;
    let timer=enrollment128::native(TIMER128)?;
    enrollment128::timer_profile(&timer,&to_bound(&e["timer_source"])?,true)?;
    // Accessible capsule bindings, never root-only enrollment/guard ancestors.
    let root=Path::new("/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work");
    let compact_path=root.join("enrollment-capsule.json");
    let compact=Bound{path:compact_path.clone(),sha256:storage::sha(&fs::read(&compact_path)?)};
    let capsule_value=immutable(&compact)?;
    ensure!(capsule_value["parent_invocation_id"]==iid && capsule_value["admission"]==e["admission"]
        && capsule_value["input_policy"]==e["input_policy"],"first128 readable capsule crossed");
    let first_guard=to_bound(&capsule_value["first_guard"])?;
    let compact_guard=immutable(&first_guard)?;
    ensure!(compact_guard["original_first_guard"]==e["first_guard"]
        && first_guard.path==root.join("first-guard-capsule.json"),"first128 readable original guard lineage crossed");
    enrollment128::held_owner(&e,&enrollment128::native(PARENT128)?)?;
    let end_native=native_capability::validate(&input_bound,&inputs,&admission_spec.native_finalizer_completion)?;
    ensure!(end_native.evidence()==native_retained.evidence()
        && current_phase::validate(&s.current_phase_ledger)?==phase,"native retention or current phase changed before release");
    let end_view=memory::admission_bridge::from_current_reader(&s.memory_request,now()?)?;
    let end_data=data::select(&end_view,&s.data_policy,&s.data_policy_seal,now()?)?;
    let end_budget=candidate_memory128::compose(&end_view,&end_data,&phase,&end_native,
        &before,&after,candidate_memory128::Stage::Enrolled(&s.enrollment))?;
    ensure!(end_budget.evidence()==budget.evidence(),"composed native memory/DATA changed before release");
    end_budget.host_fit(host)?;
    capsule(&format!("release-{iid}.json"),&json!({"schema":"epoch163-first-output128-release-v1",
        "spec":sb,"issuer":image,"retained_native128_budget_serde_sha256":storage::sha(&serde_json::to_vec(budget.evidence())?),"parent_invocation_id":iid,"parent_pid":pid,"plan":s.runtime_plan,
        "admission":e["admission"],"first_guard":first_guard,"enrollment":compact,
        "recorded_unix_seconds":now()?,"publication_authorized":false,"r2_mutations":false}))?;
    Ok(())
}
