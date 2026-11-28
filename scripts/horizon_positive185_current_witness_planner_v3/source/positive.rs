//! Additive positive48GiB metadata planner. No native/cloud/clock/admission calls.
use crate::{lineage, resources, storage::{self, Bound}, Role};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs::{self, File}, os::unix::fs::{DirBuilderExt, MetadataExt}, path::{Path, PathBuf}};

const ROOT: &str = "/home/sol/.jetstreamer-private/epoch185-driver11-current-witness-planner-qa-20261108-v3";
const FULL_READER_PATH: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2";
const FULL_READER_SHA: &str = "d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470";
const FULL_READER_ARTIFACT_SHA: &str = "fb6f325b7ce2c62164a30ad9dedb0b044a9974f32383d85bcf647cc317e06429";
const FULL_READER_SEAL_SHA: &str = "4f4bf03154dff384075b9f1fcd6b1ff29b1d7b37e5a5604339b01371b5dafd5c";
pub const EPOCH_FIRST: u64 = 79_920_000;
pub const PREFIX_LAST: u64 = 80_351_283;
pub const EPOCH_LAST: u64 = 80_351_999;
pub const OLD_MAX_RUNTIME: u64 = 259_200;
pub const POSITIVE_MEMORY: u64 = 48u64 << 30;
const SETUP: u64 = 600;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Purpose { BoundedNativeProbe, CheckpointPrefixCompletion, FullEpochSuccessor }
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub purpose: Purpose,
    pub actor_memory_bytes: u64,
    pub setup_deadline_seconds: u64,
    pub useful_runtime_seconds: u64,
    pub estimated_useful_work_millis: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    complete_tuple: Bound,
    phase_ledger: Bound,
    reviewed_phase_ledger: Bound,
    protected_exporter_plan: Bound,
    accounting_role: Role,
    native185_capture_role: Role,
    full_reader_role: Role,
    input_package_seal: Bound,
    accepted_local_integrity_basis: Bound,
    original_restore_receipt: Bound,
    status_readback: Bound,
    generation: String,
    profile: Profile,
}
fn add(a:u64,b:u64)->Result<u64>{a.checked_add(b).context("positive integer overflow")}
fn mul(a:u64,b:u64)->Result<u64>{a.checked_mul(b).context("positive integer overflow")}
fn output_path(tuple:&str,profile:&str)->Result<PathBuf>{
    ensure!(storage::hex(tuple,64)&&storage::hex(profile,64),"positive tuple/profile digest namespace");
    Ok(Path::new(ROOT).join(format!("generated-positive-{tuple}-{profile}")))
}

/// Existing72h driver cannot be relabeled full. A successor plan is never an
/// existing-driver envelope or a claim that a new driver/native route is qualified.
fn profile_policy(p:&Profile, full_estimate:u64)->Result<Value>{
    ensure!(p.actor_memory_bytes==POSITIVE_MEMORY && p.actor_memory_bytes<=195_084_404_736
        && p.setup_deadline_seconds==SETUP && full_estimate>0,"positive48GiB/setup/estimate profile");
    let duration=mul(p.useful_runtime_seconds,1000)?;
    match p.purpose {
        Purpose::BoundedNativeProbe => ensure!((600..=14_400).contains(&p.useful_runtime_seconds),
            "readiness probe is finite diagnostic work, not a full-duration completion"),
        Purpose::CheckpointPrefixCompletion => {
            let slots=PREFIX_LAST-EPOCH_FIRST+1;
            let minimum=add(mul(full_estimate,slots)?,EPOCH_LAST-EPOCH_FIRST)?/(EPOCH_LAST-EPOCH_FIRST+1);
            ensure!(p.estimated_useful_work_millis>=minimum,
                "prefix estimate omits nearly all full-epoch replay work");
            ensure!(p.useful_runtime_seconds<=OLD_MAX_RUNTIME-120
                && duration>=p.estimated_useful_work_millis,
                "existing72h checkpoint driver cannot fund measured prefix completion; qualify distinct successor");
        }
        Purpose::FullEpochSuccessor => {
            ensure!((OLD_MAX_RUNTIME+1..=7*86_400).contains(&p.useful_runtime_seconds)
                && p.estimated_useful_work_millis>=full_estimate
                && duration>=p.estimated_useful_work_millis,
                "finite full successor must fund the bound measured estimate within separately reviewed7day ceiling");
        }
    }
    let old_route=p.purpose!=Purpose::FullEpochSuccessor;
    Ok(json!({"schema":"epoch185-explicit-positive-profile-v1","profile":p,
        "epoch_start":EPOCH_FIRST,"epoch_end":EPOCH_LAST,"checkpoint_prefix_end":PREFIX_LAST,
        "remaining_suffix_slots":EPOCH_LAST-PREFIX_LAST,"selected_runtime_millis":duration,
        "bound_full_epoch_estimate_millis":full_estimate,
        "existing_driver_route_supported":old_route,"full_epoch_route_qualified":false,
        "existing_driver_admission_duration_seconds":if old_route {Some(add(add(p.useful_runtime_seconds,SETUP)?,120)?)} else {None},
        "checkpoint_only":old_route,"bounded_probe_only":p.purpose==Purpose::BoundedNativeProbe,
        "full_epoch_completion_claimed":false,"admission_authorized":false,"publication_authorized":false,
        "successor_source_gates":if old_route {json!([])} else {json!([
            "Distinct driver profile and finite useful-work cap; preserve original72h driver/pins/tests",
            "Full80351999-boundary replay/output validation or qualified checkpoint-plus716-slot suffix/assembly",
            "Native capture/admission259800-second hard ceiling and exact80351283/driver0a7dd pins require separate successor",
            "Same new qualified current reader/Frame/fleet consumers must recognize exact successor without namespace bypass",
            "Qualified output terminal/root semantics and full/plugin/both-boundary verification before publication"
        ])}}))
}
fn positive_raw(raw:&str,generation:&str)->String{
    raw.replace("missing-token","positive").replace("20261106-v14",generation)
}
fn templates(profile:&Profile, floor:u64,generation:&str)->Result<Value>{
    ensure!(profile.purpose!=Purpose::FullEpochSuccessor,"no existing-driver template for unqualified successor");
    ensure!(!generation.is_empty()&&generation.len()<=64
        && generation.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_".contains(&b)),
        "positive generation syntax");
    let mut admission:Value=serde_json::from_str(&positive_raw(include_str!("templates-driver11/admission.json"),generation))?;
    admission["memory_max_bytes"]=json!(profile.actor_memory_bytes);admission["minimum_free_bytes"]=json!(floor);
    let mut envelope:Value=serde_json::from_str(&positive_raw(include_str!("templates-driver11/envelope.json"),generation))?;
    envelope["limits"]["memory"]=json!(profile.actor_memory_bytes);
    envelope["setup_deadline_seconds"]=json!(SETUP);
    envelope["plan"]["maximum_runtime_seconds"]=json!(profile.useful_runtime_seconds);
    envelope["plan"]["minimum_free_bytes"]=json!(floor);
    let actor=positive_raw(include_str!("templates-driver11/actor.service"),generation)
        .replace("MemoryHigh=2147483648",&format!("MemoryHigh={}",profile.actor_memory_bytes))
        .replace("MemoryMax=2147483648",&format!("MemoryMax={}",profile.actor_memory_bytes))
        .replace("TimeoutStartSec=120","TimeoutStartSec=720")
        .replace("RuntimeMaxSec=600",&format!("RuntimeMaxSec={}",profile.useful_runtime_seconds))
        .replace("original-deadline positive native qualification","original positive600s setup and bounded checkpoint-prefix replay");
    let timer=positive_raw(include_str!("templates-driver11/guard.timer"),generation);
    let guard=positive_raw(include_str!("templates-driver11/guard.service"),generation);
    let timer_sha=storage::sha(timer.as_bytes());
    envelope["timer_service"]["sha256"]=json!(timer_sha);
    let mut task:Value=serde_json::from_str(&positive_raw(include_str!("templates-driver11/task-spec.json"),generation))?;
    task["native_spec"]["timer_source"]["sha256"]=json!(timer_sha);
    ensure!(envelope["plan"]["target_slot"]==PREFIX_LAST&&envelope["plan"]["terminal_slot"]==PREFIX_LAST
        && admission["prefix_only"]==true&&admission["ordinary_full_replay_authorized"]==false,
        "positive metadata must not relabel old checkpoint prefix as full");
    Ok(json!({"schema":"epoch185-positive-original600s-unissued-templates-v1",
        "admission":admission,"envelope":envelope,"actor":actor,"guard":guard,"timer":timer,
        "task_capture_spec":task,"all_dynamic_bindings_still_required":true,
        "issued_at_or_expiry_materialized":false,"normal_seal_or_admission_issued":false}))
}
// Exact operational helper13 witness/terminal145 reader already authenticated by memory4/DATA4.
// No caller-selected reader allowlist, image alias or artifact/seal substitution.
fn current_reader_role(role:&Role)->Result<Value>{
    let parent=Path::new(FULL_READER_PATH).parent().context("current reader package")?;
    ensure!(role.artifact.path==parent.join("artifact-proof.json")
        &&role.artifact.sha256==FULL_READER_ARTIFACT_SHA
        &&role.normal_seal.path==parent.join("deployment-seal-receipt.json")
        &&role.normal_seal.sha256==FULL_READER_SEAL_SHA,
        "current reader artifact/normal seal differs from accepted final-role package");
    lineage::role(&role.image,&role.artifact,&role.normal_seal,FULL_READER_PATH,FULL_READER_SHA)
}
fn validate_original_reader(reader_bound:&Bound,reader:&Value,completion:&Value,selected:&Bound)->Result<()>{
    let n=&completion["original_native"];
    ensure!(reader["image"]==json!(selected)
        && reader["raw_history_preserved"]==true&&reader["all_DATA_promises_preserved"]==true
        && completion["reader_proof"]==json!(reader_bound)&&completion["program"]==reader["image"]
        && completion["original_outer_reaped"]==true&&completion["original_cgroup_empty"]==true
        && completion["original_descriptors_drained"]==true&&n["InvocationID"]==reader["invocation_id"]
        && n["Result"]=="success"&&n["ExecMainStatus"]=="0"&&n["MainPID"]=="0"
        && n["ControlPID"]=="0"&&n["Job"]==""&&n["NRestarts"]=="0",
        "positive original current full reader/image/completion/history missing");
    Ok(())
}
pub fn materialize(request_bound:&Bound,self_image:&Bound)->Result<Value>{
    let s:Request=serde_json::from_value(storage::json(request_bound)?)?;
    ensure!(!s.generation.is_empty()&&s.generation.len()<=64
        && s.generation.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_".contains(&b)),
        "positive generation syntax");
    let namespace=storage::sha(&serde_json::to_vec(&json!({"profile":s.profile,"generation":s.generation}))?);
    let output_directory=output_path(&s.complete_tuple.sha256,&namespace)?;
    ensure!(s.schema=="epoch185-positive-metadata-plan-request-v1"
        && !output_directory.try_exists()?,"positive request/exact absent output namespace");
    let parent=output_directory.parent().context("positive output parent")?;
    let pm=fs::symlink_metadata(parent)?;
    ensure!(parent.canonicalize()?==parent&&pm.is_dir()&&pm.uid()==0&&pm.mode()&0o777==0o700,
        "positive private output custody");
    let tuple=storage::json(&s.complete_tuple)?;
    ensure!(tuple["schema"]=="horizon-existing-completed-tuple-metadata-binding-v1"
        && tuple["metadata_only_no_admission_or_new_resource_credit"]==true,"positive complete tuple scope");
    let (_,components)=storage::member(&tuple,"components")?;
    let (memory_bound,memory)=storage::member(&components,"actual_memory_selection")?;
    let (data_bound,data)=storage::member(&components,"actual_DATA_selection")?;
    ensure!(data["memory_selection"]==json!(memory_bound),"positive typed memory/DATA parent crossed");
    let current=lineage::tuple(&memory,&data,&tuple)?;
    let (reader_bound,reader)=storage::member(&memory["selection"]["request"],"current_reader")?;
    let (completion_bound,completion)=storage::member(&memory["selection"]["request"],"current_reader_acceptance")?;
    validate_original_reader(&reader_bound,&reader,&completion,&s.full_reader_role.image)?;
    let (raw_bound,raw)=storage::member(&reader,"accounting")?;
    let ledger=storage::json(&s.phase_ledger)?;
    let review=storage::json(&s.reviewed_phase_ledger)?;
    ensure!(review["schema"]=="horizon-epoch185-positive-phase-ledger-acceptance-v1"
        && review["phase_ledger"]==json!(s.phase_ledger)&&review["raw_accounting"]==json!(raw_bound)
        && review["current"]==current&&review["protected_exporter_plan"]==json!(s.protected_exporter_plan)
        && review["all_raw_claims_preserved"]==true&&review["no_resource_credit_bytes"]==0
        && review["normal_external_pool_bytes"]==6u64<<30&&review["closed_QA_additional_memory_bytes"]==0
        && review["admission_authorized"]==false,"positive ledger requires explicit reviewed same-tuple successor");
    let mut projection=resources::project_positive(&ledger,&tuple,&raw,&memory,&data)?;
    projection["sources"]=resources::projection_sources(&s.complete_tuple,&s.phase_ledger,&raw_bound);
    let live=&raw["live145_prefix_export_after"];
    ensure!(live.is_object()&&raw["live145_prefix_export_before"]["plan"]==live["plan"]
        && live["plan"]==json!(s.protected_exporter_plan)
        && raw["live145_minimum_available_memory_bytes"]==642177138688u64,
        "positive plan requires genuinely accounted current live145 and unchanged memory floor");
    let exporter=storage::json(&s.protected_exporter_plan)?;
    ensure!(exporter["schema"]=="horizon-epoch145-private-prefix-extractor-plan-v1"
        && exporter["minimum_available_memory_bytes"]==642177138688u64
        && live["peer"]["minimum_available_memory_bytes"]==642177138688u64
        && live["peer"]["credit_bytes"]==0&&live["peer"]["resource_release_qualified"]==false,
        "positive plan cannot release or weaken live exporter");
    let floor=storage::n(&projection,"minimum_free_bytes_for_future_template")?
        .max(storage::n(&exporter,"minimum_free_bytes")?);
    projection["minimum_free_bytes_for_future_template"]=json!(floor);
    projection["inherited_exporter_available_memory_floor_bytes"]=json!(642177138688u64);
    projection["protected_exporter_plan"]=json!(s.protected_exporter_plan);
    let roles=json!({
        "accounting":lineage::role(&s.accounting_role.image,&s.accounting_role.artifact,&s.accounting_role.normal_seal,lineage::ACCOUNTING_PATH,lineage::ACCOUNTING_SHA)?,
        "native185_capture":lineage::role(&s.native185_capture_role.image,&s.native185_capture_role.artifact,&s.native185_capture_role.normal_seal,lineage::DRIVER11_NATIVE_PATH,lineage::DRIVER11_NATIVE_SHA)?,
        "current_reader":current_reader_role(&s.full_reader_role)?,
        "same_new_image_required_for_post_enrollment_reader_and_acceptance":true});
    let seal=storage::json(&s.input_package_seal)?;let restore=storage::json(&s.original_restore_receipt)?;
    lineage::retained_inputs(&seal,&restore)?;storage::json(&s.accepted_local_integrity_basis)?;
    let anchor=lineage::directory_anchor(&memory,&current)?;
    let status=storage::json(&s.status_readback)?;
    ensure!(status["schema"]=="horizon-status-only-correction-v1"&&status["epoch"]==185
        && status["authenticated_readback"]==true&&status["owner_evidence"]["current_operator"]=="/root"
        && status["after_status"]["phase"]=="verification"
        && storage::n(&status["after_status"],"estimated_remaining_millis")?>0,
        "positive planning requires real Root numeric status readback");
    let full_estimate=storage::n(&status["estimate_parts_millis"],
        "full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis")?;
    let profile=profile_policy(&s.profile,full_estimate)?;
    let unissued=if s.profile.purpose==Purpose::FullEpochSuccessor {None}
        else {Some(templates(&s.profile,floor,&s.generation)?)};
    let sequence=crate::final_window::source_sequence(&s.full_reader_role.image);
    // Planning never issues wall-clock values or treats a stale tuple as fresh.
    fs::DirBuilder::new().mode(0o700).create(&output_directory)?;
    let mut outputs=vec![
        storage::save(&output_directory,"RESOURCE_PLAN_NOT_ADMISSION.json",&projection)?,
        storage::save(&output_directory,"EXPLICIT_PROFILE_NOT_ADMISSION.json",&profile)?,
        storage::save(&output_directory,"HELPER_ROLES.json",&roles)?,
        storage::save(&output_directory,"LIVE_CONTROLLER_DIRECTORY_ANCHOR_PLAN.json",&anchor)?,
        storage::save(&output_directory,"FINITE_SEQUENCE_SOURCE_CONTRACT.json",&sequence)?,
    ];
    if let Some(v)=unissued {outputs.push(storage::save(&output_directory,"POSITIVE_TEMPLATES_UNISSUED.json",&v)?);}
    let manifest=json!({"schema":"epoch185-positive48GiB-plan-materialized-not-admission-v1",
        "request":request_bound,"program":self_image,"complete_tuple":s.complete_tuple,
        "phase_ledger":s.phase_ledger,"reviewed_phase_ledger":s.reviewed_phase_ledger,
        "current":current,"reader":reader_bound,"reader_completion":completion_bound,
        "memory_selection":memory_bound,"DATA_selection":data_bound,"status_readback":s.status_readback,
        "profile":s.profile,"outputs":outputs,"all_raw_claims_and_live145_floor_preserved":true,
        "new_resource_samples":0,"native_calls":0,"new_snapshot_body_hash":false,
        "original_admission_clocks_issued":false,"fresh_current_capacity_claimed":false,
        "admission_issued":false,"replay_launch_authorized":false,"publication_authorized":false,
        "full_epoch_route_qualified":false,"r2_mutations":false});
    let out=storage::save(&output_directory,"PLAN_MANIFEST_NOT_ADMISSION.json",&manifest)?;
    File::open(parent)?.sync_all()?;
    Ok(json!({"metadata_plan":out,"admission_issued":false,"full_epoch_route_qualified":false}))
}
#[cfg(test)]
mod tests{
    use super::*;
    fn profile(purpose:Purpose,seconds:u64)->Profile{Profile{purpose,actor_memory_bytes:48u64<<30,
        setup_deadline_seconds:600,useful_runtime_seconds:seconds,estimated_useful_work_millis:413_404_206}}
    #[test] fn negative_budget_and_extended_setup_cannot_enter_positive_profile(){
        let mut p=profile(Purpose::BoundedNativeProbe,3600);profile_policy(&p,413_404_206).unwrap();
        p.actor_memory_bytes=2u64<<30;assert!(profile_policy(&p,413_404_206).is_err());
        p.actor_memory_bytes=48u64<<30;p.setup_deadline_seconds=601;
        assert!(profile_policy(&p,413_404_206).is_err());
    }
    #[test] fn peer_rate_cannot_fit_checkpoint_completion_into_existing72hours(){
        assert!(profile_policy(&profile(Purpose::CheckpointPrefixCompletion,259080),413_404_206).is_err());
    }
    #[test] fn full_successor_funds_estimate_but_never_gets_old_driver_or_completion_authority(){
        let p=profile(Purpose::FullEpochSuccessor,604800);let v=profile_policy(&p,413_404_206).unwrap();
        assert_eq!(v["existing_driver_route_supported"],false);
        assert_eq!(v["full_epoch_route_qualified"],false);
        assert_eq!(v["remaining_suffix_slots"],716);
        assert!(templates(&p,5_074_152_197_938,"fixture-v1").is_err());
    }
    #[test] fn positive_templates_consistently_bind48g600s_without_materializing_any_clock(){
        let p=profile(Purpose::BoundedNativeProbe,3600);
        let v=templates(&p,5_074_152_197_938,"fixture-v1").unwrap();
        assert_eq!(v["admission"]["memory_max_bytes"],48u64<<30);
        assert_eq!(v["envelope"]["limits"]["memory"],48u64<<30);
        assert_eq!(v["envelope"]["setup_deadline_seconds"],600);
        assert_eq!(v["envelope"]["plan"]["target_slot"],PREFIX_LAST);
        assert!(v["admission"]["issued_at"].get("$actual_root_binding").is_some());
        assert!(v["actor"].as_str().unwrap().contains("MemoryMax=51539607552"));
        assert!(v["actor"].as_str().unwrap().contains("TimeoutStartSec=720"));
    }
    #[test] fn profile_changes_get_disjoint_retry_stable_output_and_no_traversal(){
        let a=output_path(&"a".repeat(64),&"b".repeat(64)).unwrap();
        assert_ne!(a,output_path(&"a".repeat(64),&"c".repeat(64)).unwrap());
        assert_eq!(a,output_path(&"a".repeat(64),&"b".repeat(64)).unwrap());
        assert!(output_path("../escape",&"b".repeat(64)).is_err());
    }
}

#[cfg(test)]
mod qualified_current_reader_tests {
    use super::*;
    fn role()->Role {
        let parent=Path::new(FULL_READER_PATH).parent().unwrap();
        Role {
            image:Bound{path:FULL_READER_PATH.into(),sha256:FULL_READER_SHA.into()},
            artifact:Bound{path:parent.join("artifact-proof.json"),sha256:FULL_READER_ARTIFACT_SHA.into()},
            normal_seal:Bound{path:parent.join("deployment-seal-receipt.json"),sha256:FULL_READER_SEAL_SHA.into()},
        }
    }
    // This test reads actual qualified package metadata only. It neither reads
    // the executable body nor queries native state or claims a fresh tuple.
    #[test]
    fn actual_helper13_witness_terminal145_normal_package_is_accepted_without_replay_promotion(){
        let r=role();let actual=current_reader_role(&r).unwrap();
        assert_eq!(actual["image"],json!(r.image));
        assert_eq!(actual["artifact_qualification"],json!(r.artifact));
        assert_eq!(actual["normal_seal"],json!(r.normal_seal));
        assert_eq!(actual["capture_cold185_startpre_task"],false);
        assert_eq!(actual["image_body_rehash_pending_future_readiness"],true);
    }
    #[test]
    fn obsolete_reader_or_same_bytes_at_another_package_cannot_replace_final_role(){
        let mut old=role();
        old.image=Bound{
            path:"/usr/local/lib/jetstreamer/horizon-live145-prefix-current-accounting-tools-20261107-v1/jetstreamer-r2".into(),
            sha256:"50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a".into()};
        assert!(current_reader_role(&old).is_err());
        let mut preterminal=role();
        preterminal.image=Bound{
            path:"/usr/local/lib/jetstreamer/horizon-live145-genuine-frame-final-helper-tools-20261107-v1/jetstreamer-r2".into(),
            sha256:"012b6be173815c8c760a445c343e21b5082ce1ea8ef29097cec7019c2602ae46".into()};
        assert!(current_reader_role(&preterminal).is_err());
        let mut alias=role();
        alias.image.path="/usr/local/lib/jetstreamer/another-package-with-identical-helper13-bytes/jetstreamer-r2".into();
        assert!(current_reader_role(&alias).is_err());
    }
    #[test]
    fn artifact_and_normal_seal_are_independently_bound_to_accepted_final_package(){
        let mut crossed=role();crossed.artifact.sha256="0".repeat(64);
        assert!(current_reader_role(&crossed).is_err());
        let mut crossed=role();crossed.normal_seal.sha256="0".repeat(64);
        assert!(current_reader_role(&crossed).is_err());
        let mut crossed=role();
        crossed.artifact.path="/usr/local/lib/jetstreamer/other/artifact-proof.json".into();
        assert!(current_reader_role(&crossed).is_err());
    }
    fn completion_fixture()->(Bound,Value,Value){
        // Synthetic pure gate fixture only, never an operational acceptance.
        let reader_bound=Bound{path:"/fixture/original-reader.json".into(),sha256:"a".repeat(64)};
        let reader=json!({"image":role().image,"invocation_id":"b".repeat(32),
            "raw_history_preserved":true,"all_DATA_promises_preserved":true});
        let completion=json!({"reader_proof":reader_bound,"program":reader["image"],
            "original_outer_reaped":true,"original_cgroup_empty":true,"original_descriptors_drained":true,
            "original_native":{"InvocationID":"b".repeat(32),"Result":"success","ExecMainStatus":"0",
                "MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0"}});
        (reader_bound,reader,completion)
    }
    #[test]
    fn current_reader_and_its_original_completion_must_use_same_selected_image(){
        let (b,reader,completion)=completion_fixture();
        validate_original_reader(&b,&reader,&completion,&role().image).unwrap();
        let mut old=reader.clone();
        old["image"]["sha256"]=json!("50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a");
        assert!(validate_original_reader(&b,&old,&completion,&role().image).is_err());
        let mut crossed=completion;
        crossed["program"]["path"]=json!("/different/original-reader");
        assert!(validate_original_reader(&b,&reader,&crossed,&role().image).is_err());
    }
    #[test]
    fn reader_pin_update_does_not_relax_original_history_completion_or_native_drain(){
        let (b,reader,completion)=completion_fixture();
        for pointer in ["/original_outer_reaped","/original_cgroup_empty","/original_descriptors_drained"]{
            let mut bad=completion.clone();*bad.pointer_mut(pointer).unwrap()=json!(false);
            assert!(validate_original_reader(&b,&reader,&bad,&role().image).is_err(),"{pointer}");
        }
        let mut restarted=completion.clone();restarted["original_native"]["NRestarts"]=json!("1");
        assert!(validate_original_reader(&b,&reader,&restarted,&role().image).is_err());
        let mut crossed=completion;crossed["reader_proof"]["sha256"]=json!("c".repeat(64));
        assert!(validate_original_reader(&b,&reader,&crossed,&role().image).is_err());
        let mut history=reader;history["all_DATA_promises_preserved"]=json!(false);
        let (_,_,good)=completion_fixture();
        assert!(validate_original_reader(&b,&history,&good,&role().image).is_err());
    }
}

#[cfg(test)] mod driver11_materialized_role_regression {
use super::*;
#[test] fn positive_templates_bind_actual_driver11_without_changing_historical_templates() {
 let p=Profile{purpose:Purpose::BoundedNativeProbe,actor_memory_bytes:48u64<<30,setup_deadline_seconds:600,useful_runtime_seconds:14400,estimated_useful_work_millis:413404206};
 let v=templates(&p,5255032943252,"driver11-regression").unwrap();
 assert_eq!(v["envelope"]["self_program"],"/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold");
 assert_eq!(v["envelope"]["self_sha256"],"bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2");
 for field in ["actor","guard"] {let text=v[field].as_str().unwrap();assert!(text.contains("/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold"));assert!(text.contains("--self-sha256 bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2"));assert!(!text.contains("guarded-adapter-v10"));}
 assert!(include_str!("templates/actor.service").contains("guarded-adapter-v10"));
 assert_eq!(v["envelope"]["plan"]["terminal_slot"],80351283);
 assert_eq!(v["admission"]["ordinary_full_replay_authorized"],false);
}
}
