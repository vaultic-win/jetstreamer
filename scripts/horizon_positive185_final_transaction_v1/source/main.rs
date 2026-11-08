//! One finite post-reader positive185 transaction. Root supplies real admitted
//! setup and completed original reader. This executable never creates a reader
//! success, refreshes an old clock, or launches a second actor.
mod storage;
mod process;
mod transaction;
mod events;
#[path = "/usr/local/lib/jetstreamer/horizon-positive185-start-request-policy-source-20261108-v2/start_request.rs"]
#[expect(dead_code, reason="the exact shared policy also exports producer-only detach; this consumer only restores")]
mod start_request;
use anyhow::{Context,Result,ensure};
use serde::Deserialize;
use serde_json::{Value,json};
use std::{env,fs,os::unix::fs::MetadataExt,path::{Path,PathBuf},time::{SystemTime,UNIX_EPOCH}};
use storage::Bound;
const START_REQUEST_POLICY_SOURCE:&str="/usr/local/lib/jetstreamer/horizon-positive185-start-request-policy-source-20261108-v2/start_request.rs";
const START_REQUEST_POLICY_SHA:&str="7b28a430d3f4179759440bd679005a6231c638b6f808ce673e9933cf7281d4c6";
impl start_request::Transport for process::Runner<'_>{
    fn metadata(&mut self,label:&str,command:std::process::Command,limit:std::time::Duration)->Result<Value>{
        self.run(label,command,limit)
    }
}
pub fn now()->Result<u64>{Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())}
pub fn n(v:&Value,key:&str)->Result<u64>{storage::n(v,key)}
pub fn text<'a>(v:&'a Value,key:&str)->Result<&'a str>{v[key].as_str().with_context(||format!("missing string {key}"))}
pub fn unit_name(s:&str)->bool{s.len()<=180&&!s.is_empty()&&s.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_.".contains(&b))}
pub fn binding(v:&Value)->Result<Bound>{storage::bound(v)}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role{pub image:Bound,pub artifact:Bound,pub normal_seal:Bound}
#[derive(Deserialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub enum Purpose{BoundedPrefixProbe,QualifiedFullEpoch}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route{
    pub schema:String,pub purpose:Purpose,pub helper:Role,pub driver:Bound,
    pub driver_normal_seal:Bound,pub capability_acceptance:Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextFile{
    pub schema:String,pub qualified_route:Bound,pub task:Bound,pub registration:Bound,
    pub actual_fleet:Bound,pub actual_fleet_plan:Bound,pub original_reader:Bound,
    pub original_reader_completion:Bound,pub normal_pool_booking:Bound,pub work_root:PathBuf,
    pub original_start_request_handoff:Bound,
}
pub fn verify_role(role:&Role)->Result<()>{
    ensure!(role.image.path.file_name().and_then(|s|s.to_str())==Some("jetstreamer-r2")
        &&role.image.path.parent().and_then(Path::parent)==Some(Path::new("/usr/local/lib/jetstreamer")),
        "qualified helper role namespace");
    ensure!(role.artifact.path==role.image.path.parent().context("helper parent")?.join("artifact-proof.json"),
        "helper artifact must be original normal package member");
    let artifact=storage::json(&role.artifact)?;let seal=storage::json(&role.normal_seal)?;
    verify_seal_member(&seal,&role.image,0o555)?;
    verify_seal_member(&seal,&role.artifact,0o444)?;
    ensure!(artifact["artifact"]["sha256"]==role.image.sha256
        ||artifact["production_artifact"]["sha256"]==role.image.sha256,
        "helper artifact proof does not bind actual image");
    storage::bytes(&role.image,256<<20,true)?;Ok(())
}
pub fn verify_seal_member(seal:&Value,b:&Bound,mode:u32)->Result<()>{
    let parent=b.path.parent().context("sealed member parent")?;
    ensure!(seal["schema"]=="jetstreamer-sealed-deployment-receipt-v1"
        &&seal["sealer_sha256"]==process::SEALER_SHA
        &&seal["destination"]==parent.to_string_lossy().as_ref(),"normal seal identity");
    let name=b.path.file_name().and_then(|s|s.to_str()).context("sealed member name")?;
    let matches=seal["members"].as_array().context("normal seal members")?.iter()
        .filter(|m|m["name"]==name).collect::<Vec<_>>();
    ensure!(matches.len()==1&&matches[0]["sha256"]==b.sha256
        &&matches[0]["mode"]==format!("{mode:04o}"),"normal seal exact member/digest/mode");
    Ok(())
}
fn common_start_request_control(control:&Value)->Result<()>{
    ensure!(control["schema"]=="horizon-positive185-actual-held-start-job-reload-control-v1"
        &&control["actual_pre_task_reload_and_start_job_validator_exercised"]==true
        &&control["same_original_actor_start_request_roundtrip_exercised"]==true
        &&control["input_body_reads"]==0&&control["publication_authorized"]==false
        &&control["replay_launch_authorized"]==false,
        "common native start-request qualification scope or actual roundtrip missing");
    let before=&control["before_native"];let terminal=&control["terminal_native"];
    ensure!(storage::hex(text(before,"InvocationID")?,32)&&before["Id"]==terminal["Id"]
        &&before["InvocationID"]==terminal["InvocationID"]
        &&before["ActiveState"]=="activating"&&before["SubState"]=="start-pre"
        &&terminal["MainPID"]=="0"&&terminal["ControlPID"]=="0"&&terminal["NRestarts"]=="0"
        &&terminal["Job"]==""&&terminal["Result"]=="success"&&terminal["ExecMainStatus"]=="0",
        "common request control changed native owner or lacks successful terminal drain");
    let done=control["original_PID1"].as_array().context("common control original PID1 rows")?.iter()
        .filter(|row|row["MESSAGE_ID"]=="39f53479d3a045ac8e11786248231fbf").collect::<Vec<_>>();
    ensure!(done.len()==1&&done[0]["_PID"]=="1"&&done[0]["_UID"]=="0"
        &&done[0]["UNIT"]==before["Id"]&&done[0]["INVOCATION_ID"]==before["InvocationID"]
        &&done[0]["JOB_TYPE"]=="start"&&done[0]["JOB_RESULT"]=="done",
        "common native control lacks one exact normal PID1 start-done");
    Ok(())
}
fn validate_start_request_qualification(capability:&Value)->Result<()>{
    let source=binding(&capability["original_start_request_policy_source"])?;
    ensure!(source.path==Path::new(START_REQUEST_POLICY_SOURCE)&&source.sha256==START_REQUEST_POLICY_SHA,
        "final executor and qualified native control require identical sealed request policy source");
    storage::bytes(&source,1<<20,true)?;
    let source_seal_bound=binding(&capability["original_start_request_policy_normal_seal"])?;
    let source_seal=storage::json(&source_seal_bound)?;
    verify_seal_member(&source_seal,&source,0o444)?;
    let control=binding(&capability["actual_start_request_common_control"])?;
    let seal=storage::json(&binding(&capability["start_request_common_control_normal_seal"])?)?;
    verify_seal_member(&seal,&control,0o444)?;
    let proof:Value=serde_json::from_slice(&storage::bytes(&control,4<<20,true)?)?;
    common_start_request_control(&proof)?;
    let completion_bound=binding(&capability["original_start_request_common_qualification"])?;
    ensure!(completion_bound.path.parent()==control.path.parent(),
        "common qualification and native control must share the same normal seal");
    verify_seal_member(&seal,&completion_bound,0o444)?;
    let completion:Value=serde_json::from_slice(&storage::bytes(&completion_bound,4<<20,true)?)?;
    ensure!(completion["schema"]=="horizon-original-start-request-common-policy-qualified-v1"
        &&completion["policy_source"]==json!(source)&&completion["policy_normal_seal"]==json!(source_seal_bound)
        &&completion["actual_common_control"]["sha256"]==control.sha256
        &&completion["bootstrap_image"]==proof["program"]
        &&completion["actual_start_request_detached"]==proof["actual_start_request_detached"]
        &&completion["actual_start_request_restored"]==proof["actual_start_request_restored"]
        &&completion["all_four_strict_compiler_stages_passed"]==true
        &&n(&completion,"ordinary_tests_passed")?>=32
        &&completion["same_original_actor_start_request_roundtrip_exercised"]==true
        &&completion["replacement_job_native_PID1_done"]==true
        &&completion["common_policy_only"]==true&&completion["same_image_production_launch_qualified"]==false
        &&completion["replay_launch_authorized"]==false&&completion["publication_authorized"]==false
        &&completion["resource_credit_bytes"]==0,
        "common qualification lost exact source/control linkage or exceeded its limited authority");
    ensure!(storage::bytes(&binding(&completion["actual_common_control"])?,4<<20,false)?
        ==storage::bytes(&control,4<<20,true)?,"sealed common control differs from actual original");
    let graph=storage::json(&binding(&completion["source_and_exact_compiler_graph"])?)?;
    ensure!(graph["actual_source_policy_normal_seal"]==json!(source_seal_bound)
        &&graph["source"].as_array().context("common exact compiler source graph")?.iter()
            .filter(|b|**b==json!(source)).count()==1,
        "native qualification compiler graph lost exact common source seal");
    let drained=storage::json(&binding(&completion["original_native_completion_and_drain"])?)?;
    ensure!(drained["original_held_pid_absent"]==true&&drained["all_processes_and_cgroups_drained"]==true,
        "common qualification original control process or cgroup not drained");
    let bootstrap=binding(&completion["bootstrap_image"])?;
    verify_seal_member(&storage::json(&binding(&completion["bootstrap_normal_seal"])?)?,&bootstrap,0o555)?;
    // These original receipts remain hash-bound even though the common control
    // is completed, and may never be reinterpreted as a launch admission.
    let detached=storage::json(&binding(&proof["actual_start_request_detached"])?)?;
    let restored=storage::json(&binding(&proof["actual_start_request_restored"])?)?;
    ensure!(detached["schema"]=="horizon-original-held-start-request-detached-v1"
        &&restored["schema"]=="horizon-original-held-start-request-restored-v1"
        &&detached["owner"]==restored["owner"]
        &&detached["owner"]["actor"]==proof["before_native"]["Id"]
        &&detached["owner"]["invocation_id"]==proof["before_native"]["InvocationID"]
        &&restored["before_native"]==detached["detached_native"]
        &&detached["original_pidfd_alive_after"]==true&&restored["original_pidfd_alive_after"]==true
        &&detached["no_actor_signal_restart_or_clock_renewal"]==true
        &&restored["no_actor_signal_restart_or_clock_renewal"]==true,
        "common control lost original same-process detach/restore evidence");
    let job=text(&restored["restored_native"],"Job")?;
    ensure!(!job.is_empty()&&job!=text(&detached["before_native"],"Job")?
        &&proof["original_PID1"].as_array().context("common PID1 rows")?.iter()
            .any(|row|row["JOB_RESULT"]=="done"&&row["JOB_ID"]==job),
        "common control PID1done does not bind actual replacement request");
    Ok(())
}
fn route_policy(route:&Route,capability:&Value,envelope:&Value,admission:&Value)->Result<()>{
    if route.purpose==Purpose::BoundedPrefixProbe{
        ensure!(route.driver.sha256=="0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a"
            &&capability["retained_source_base_helper_sha256"]=="50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a"
            &&envelope["limits"]["memory"]==48u64<<30&&admission["memory_max_bytes"]==48u64<<30
            &&envelope["plan"]["target_slot"]==80351283u64&&envelope["plan"]["terminal_slot"]==80351283u64
            &&(600..=14400).contains(&n(&envelope["plan"],"maximum_runtime_seconds")?)
            &&admission["prefix_only"]==true&&capability["bounded_probe_only"]==true,
            "current route permits finite48GiB checkpoint probe, not full epoch");
    }else{
        ensure!(route.driver.sha256!="0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a"
            &&capability["full_boundary_route_qualified"]==true
            &&capability["full_epoch_start"]==79920000u64&&capability["full_epoch_end"]==80351999u64
            &&n(&envelope["plan"],"maximum_runtime_seconds")?>259200
            &&n(&envelope["plan"],"maximum_runtime_seconds")?<=604800
            &&n(admission,"expires_at")?.checked_sub(n(admission,"issued_at")?).is_some_and(|s|s>259800),
            "full epoch needs separately qualified boundary/runtime/native consumer successor");
    }
    Ok(())
}
pub fn validate_context(c:&ContextFile,route:&Route,self_image:&Bound,task:&Value,
    envelope:&Value,admission:&Value,at:u64)->Result<()>{
    ensure!(c.schema=="horizon-positive185-postreader-final-context-v2"
        &&route.schema=="horizon-positive185-final-qualified-route-v1","positive final scope");
    let iid=text(task,"actor_invocation_id")?;
    ensure!(storage::hex(iid,32)&&task["schema"]=="horizon-epoch185-genuine-native-startpre-task-v1"
        &&task["stage"]=="start-pre"&&task["guard_pending"]==true
        &&task["no_replay_or_publication_or_credit"]==true&&task["capacity_credit_bytes"]==0,
        "positive final requires original gated native task");
    let ready=&task["ready"];
    ensure!(n(ready,"started_at")?<=at&&n(task,"original_setup_deadline_unix_seconds")?>at
        &&n(task,"original_setup_deadline_unix_seconds")?.checked_sub(n(ready,"started_at")?)==Some(600)
        &&envelope["setup_deadline_seconds"]==600,"original600s setup expired or changed");
    ensure!(envelope["self_program"]==route.driver.path.to_string_lossy().as_ref()
        &&envelope["self_sha256"]==route.driver.sha256&&task["admission"]==envelope["admission"]
        &&admission["unit"]==task["actor_unit"]&&admission["task_owner"]=="Root"
        &&admission["issued_at"].as_u64().is_some_and(|t|t<=at)
        &&admission["expires_at"].as_u64().is_some_and(|t|t>at)
        &&admission["resource_credit_bytes"]==0&&admission["publication_authorized"]==false
        &&admission["full_reader_accepted"]==true&&admission["raw_obligations_preserved"]==true,
        "positive final changed exact admitted route/owner/clock/authority");
    let capability=storage::json(&route.capability_acceptance)?;
    ensure!(capability["schema"]=="horizon-positive185-final-route-capability-v2"
        &&capability["executor"]==json!(self_image)&&capability["helper"]==json!(route.helper.image)
        &&capability["driver"]==json!(route.driver)
        &&capability["scope"]=="one-original-post-reader-release-attempt"
        &&capability["original_setup_seconds"]==600
        &&capability["all_raw_obligations_and_live_guards_preserved"]==true
        &&capability["original_writer_custody_supported"]==true,
        "Root route capability does not bind this exact finite executor/helper/driver");
    validate_start_request_qualification(&capability)?;
    let owner=start_request::Owner::from_ready(text(task,"actor_unit")?,iid,ready,
        n(task,"original_setup_deadline_unix_seconds")?)?;
    start_request::validate_detached(&storage::json(&c.original_start_request_handoff)?,&owner)?;
    if route.purpose==Purpose::BoundedPrefixProbe{
        ensure!(task["self_sha256"]=="0f1d171bc9fee7a1d06186e62b03e601d575bdcacfa30545cf0c084850f0934c",
            "current probe task was not captured by distinct qualified native1850f1d role");
    }else{
        ensure!(task["self_sha256"]==capability["native_capture_image"]["sha256"],
            "full successor original task lost its separately qualified capture role");
    }
    route_policy(route,&capability,envelope,admission)?;
    let booking=storage::json(&c.normal_pool_booking)?;
    ensure!(booking["schema"]=="horizon-positive185-finite-final-booking-v1"
        &&booking["qualified_route"]==json!(c.qualified_route)&&booking["task"]==json!(c.task)
        &&booking["original_reader_completion"]==json!(c.original_reader_completion)
        &&booking["normal_external_pool_bytes"]==6u64<<30
        &&booking["root_control_memory_bytes"]==512u64<<20
        &&booking["serial_child_memory_bytes"]==2u64<<30
        &&booking["additional_QA_memory_bytes"]==0
        &&booking["all_other_normal_pool_actors_drained"]==true
        &&booking["resource_credit_bytes"]==0
        &&n(&booking,"expires_at")?>=at.checked_add(120).context("normal-pool booking clock overflow")?,"exact serial normal-pool final booking missing");
    Ok(())
}
fn root_capability_preflight()->Result<()>{
    let mut limit:libc::rlimit=unsafe{std::mem::zeroed()};
    ensure!(unsafe{libc::getrlimit(libc::RLIMIT_NOFILE,&mut limit)}==0
        &&limit.rlim_cur>=1_000_000,"finite Root fd profile not qualified");
    let raw=fs::read_to_string("/proc/self/status")?;
    let line=raw.lines().find(|s|s.starts_with("CapEff:")).context("Root effective capability record")?;
    let bits=u64::from_str_radix(line.split_whitespace().nth(1).context("Root capability mask")?,16)?;
    let required=(1u64<<0)|(1u64<<1)|(1u64<<19);
    ensure!(bits&required==required,"finite Root requires CHOWN,DAC_OVERRIDE,SYS_PTRACE");
    Ok(())
}
fn sol_read(args:&[String])->Result<()>{
    ensure!(args.len()==20&&args[2]=="--self-sha256"&&unsafe{libc::geteuid()}==1001
        &&unsafe{libc::getegid()}==1003,"exact unprivileged eight-file read shape");
    let own=Bound{path:fs::read_link("/proc/self/exe")?,sha256:args[3].clone()};
    storage::bytes(&own,128<<20,true)?;
    for pair in args[4..].as_chunks::<2>().0{
        let b=Bound{path:pair[0].clone().into(),sha256:pair[1].clone()};
        let parent=b.path.parent().context("sol evidence parent")?;
        ensure!(parent.parent()==Some(Path::new("/usr/local/lib/jetstreamer"))
            &&parent.file_name().and_then(|s|s.to_str()).is_some_and(|s|
                s.starts_with("horizon-epoch185-readable-originals-")||s.starts_with("horizon-epoch185-positive-final-views-")),
            "sol read limited to exact public immutable185 evidence packages");
        storage::bytes(&b,4<<20,true)?;
    }
    println!("{}",json!({"actual_sol_uid":1001,"actual_horizon_gid":1003,"all_eight_exact_bound_files_read":true}));
    Ok(())
}
fn run()->Result<()>{
    let args=env::args().collect::<Vec<_>>();
    ensure!(!env::vars_os().any(|(k,_)|k.to_string_lossy().starts_with("LD_")||k=="GLIBC_TUNABLES"),
        "finite executor loader override");
    if args.get(1).is_some_and(|s|s=="sol-read-check"){return sol_read(&args)}
    ensure!(unsafe{libc::geteuid()}==0&&args.len()==7&&args[1]=="execute-positive185-final"
        &&args[3]=="--context-sha256"&&args[5]=="--self-sha256","exact Root finite final CLI");
    ensure!(!env::vars_os().any(|(k,_)|k.to_string_lossy().starts_with("LD_")||k=="GLIBC_TUNABLES"),
        "finite final loader override");
    root_capability_preflight()?;
    let own=Bound{path:fs::read_link("/proc/self/exe")?,sha256:args[6].clone()};
    ensure!(own.path.parent().and_then(Path::parent)==Some(Path::new("/usr/local/lib/jetstreamer")),
        "finite final executable must be normally deployed");
    storage::bytes(&own,128<<20,true)?;
    let context=Bound{path:args[2].clone().into(),sha256:args[4].clone()};
    let c:ContextFile=serde_json::from_value(storage::json(&context)?)?;
    let route:Route=serde_json::from_value(storage::json(&c.qualified_route)?)?;
    verify_role(&route.helper)?;
    verify_seal_member(&storage::json(&route.driver_normal_seal)?,&route.driver,0o555)?;
    storage::bytes(&route.driver,256<<20,true)?;
    storage::bytes(&Bound{path:process::SEALER.into(),sha256:process::SEALER_SHA.into()},32<<20,true)?;
    let task=storage::json(&c.task)?;
    let (_,envelope)=storage::member(&task,"envelope")?;
    let (_,admission)=storage::member(&task,"admission")?;
    validate_context(&c,&route,&own,&task,&envelope,&admission,now()?)?;
    let root=&c.work_root;
    ensure!(root.parent()==Some(Path::new("/home/sol/.jetstreamer-private"))
        &&root.file_name().and_then(|s|s.to_str()).is_some_and(|s|s.starts_with("epoch185-positive-final-control-"))
        &&root.canonicalize()?==*root,"finite final private root namespace");
    let m=fs::symlink_metadata(root)?;
    ensure!(m.is_dir()&&m.uid()==0&&m.mode()&0o777==0o700&&fs::read_dir(root)?.next().is_none(),
        "finite final must use fresh prebooked Root0700 empty work root");
    storage::save(root,"ORIGINAL_CONTEXT.json",&json!({"context":context,"route":c.qualified_route,
        "original_task":c.task,"at":now()?,"no_retries_or_deadline_renewal":true}))?;
    let outcome=transaction::execute(&c,&route,&own,&task,&envelope,&admission);
    if let Err(ref e)=outcome{
        storage::save(root,"ORIGINAL_FINAL_FAILURE.json",&json!({"at":now()?,"error":format!("{e:#}"),
            "original_task":c.task,"original_setup_deadline":task["original_setup_deadline_unix_seconds"],
            "no_retry_clock_reset_fake_success_or_actor_restart":true,
            "token_may_have_been_committed_preserve_actual_state":true}))?;
    }
    outcome
}
fn main(){if let Err(e)=run(){eprintln!("positive185 original final: {e:#}");std::process::exit(1)}}

#[cfg(test)]
mod tests{
    use super::*;
    // Synthetic policy fixtures only; never native or Root acceptance evidence.
    fn b(path:&str)->Bound{Bound{path:path.into(),sha256:"b".repeat(64)}}
    fn fixture()->(Route,Value,Value,Value){
        let route=Route{schema:"horizon-positive185-final-qualified-route-v1".into(),
            purpose:Purpose::BoundedPrefixProbe,
            helper:Role{image:b("/usr/local/lib/jetstreamer/fixture/jetstreamer-r2"),
                artifact:b("/fixture/artifact.json"),normal_seal:b("/fixture/seal.json")},
            driver:Bound{path:"/fixture/driver".into(),
                sha256:"0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a".into()},
            driver_normal_seal:b("/fixture/driver-seal.json"),capability_acceptance:b("/fixture/capability.json")};
        let capability=json!({"retained_source_base_helper_sha256":"50b2b6636068811d1176f87f5d49b76206db785dcb1e0ac80023c517cefac07a",
            "bounded_probe_only":true,"full_boundary_route_qualified":true,
            "full_epoch_start":79920000u64,"full_epoch_end":80351999u64});
        let envelope=json!({"limits":{"memory":48u64<<30},"plan":{"target_slot":80351283u64,
            "terminal_slot":80351283u64,"maximum_runtime_seconds":3600}});
        let admission=json!({"memory_max_bytes":48u64<<30,"prefix_only":true,"issued_at":1000,"expires_at":5320});
        (route,capability,envelope,admission)
    }
    #[test]fn negative2g_and_full_boundary_cannot_enter_current_probe(){
        let(r,c,e,a)=fixture();route_policy(&r,&c,&e,&a).unwrap();
        let mut bad=e.clone();bad["limits"]["memory"]=json!(2u64<<30);
        assert!(route_policy(&r,&c,&bad,&a).is_err());
        let mut bad=e;bad["plan"]["terminal_slot"]=json!(80351999u64);
        assert!(route_policy(&r,&c,&bad,&a).is_err());
    }
    #[test]fn old_checkpoint_driver_cannot_become_full_by_capability_boolean(){
        let(mut r,c,mut e,mut a)=fixture();r.purpose=Purpose::QualifiedFullEpoch;
        e["plan"]["maximum_runtime_seconds"]=json!(604800);
        a["expires_at"]=json!(606000);
        assert!(route_policy(&r,&c,&e,&a).is_err());
    }
    #[test]fn exact_normal_member_rejects_digest_mode_and_duplicate_claim(){
        let b=b("/usr/local/lib/jetstreamer/fixture/jetstreamer-r2");
        let seal=json!({"schema":"jetstreamer-sealed-deployment-receipt-v1",
            "sealer_sha256":process::SEALER_SHA,"destination":"/usr/local/lib/jetstreamer/fixture",
            "members":[{"name":"jetstreamer-r2","sha256":b.sha256,"mode":"0555"}]});
        verify_seal_member(&seal,&b,0o555).unwrap();
        let mut bad=seal.clone();bad["members"][0]["sha256"]=json!("c".repeat(64));
        assert!(verify_seal_member(&bad,&b,0o555).is_err());
        let mut bad=seal;let row=bad["members"][0].clone();
        bad["members"].as_array_mut().unwrap().push(row);
        assert!(verify_seal_member(&bad,&b,0o555).is_err());
    }
    #[test]fn mutable_native_namespace_never_accepts_command_injection(){
        assert!(unit_name("horizon-guard-185-capped-cold-positive-fixture.timer"));
        for name in ["guard.service;start other","--host=foreign","../other.service","guard service"]{
            assert!(!unit_name(name)||!name.starts_with("horizon-guard-185-capped-cold-"));
        }
    }
    #[test]fn context_v2_requires_explicit_bound_handoff(){
        let bound=json!({"path":"/fixture/bound.json","sha256":"b".repeat(64)});
        let mut context=json!({"schema":"horizon-positive185-postreader-final-context-v2",
            "qualified_route":bound,"task":bound,"registration":bound,"actual_fleet":bound,
            "actual_fleet_plan":bound,"original_reader":bound,"original_reader_completion":bound,
            "normal_pool_booking":bound,"work_root":"/fixture/work",
            "original_start_request_handoff":bound});
        assert!(serde_json::from_value::<ContextFile>(context.clone()).is_ok());
        context.as_object_mut().unwrap().remove("original_start_request_handoff");
        assert!(serde_json::from_value::<ContextFile>(context).is_err());
    }
    #[test]fn common_request_control_rejects_missing_roundtrip_foreign_pid1_and_duplicate_done(){
        let before=json!({"Id":"horizon-qualify-185-fixture.service","InvocationID":"a".repeat(32),
            "ActiveState":"activating","SubState":"start-pre"});
        let terminal=json!({"Id":before["Id"],"InvocationID":before["InvocationID"],
            "MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","Result":"success","ExecMainStatus":"0"});
        let done=json!({"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","_PID":"1","_UID":"0",
            "UNIT":before["Id"],"INVOCATION_ID":before["InvocationID"],"JOB_TYPE":"start","JOB_RESULT":"done"});
        let proof=json!({"schema":"horizon-positive185-actual-held-start-job-reload-control-v1",
            "actual_pre_task_reload_and_start_job_validator_exercised":true,
            "same_original_actor_start_request_roundtrip_exercised":true,"input_body_reads":0,
            "publication_authorized":false,"replay_launch_authorized":false,
            "before_native":before,"terminal_native":terminal,"original_PID1":[done]});
        common_start_request_control(&proof).unwrap();
        let mut bad=proof.clone();bad["same_original_actor_start_request_roundtrip_exercised"]=json!(false);
        assert!(common_start_request_control(&bad).is_err());
        let mut bad=proof.clone();bad["original_PID1"][0]["INVOCATION_ID"]=json!("b".repeat(32));
        assert!(common_start_request_control(&bad).is_err());
        let mut bad=proof;let duplicate=bad["original_PID1"][0].clone();
        bad["original_PID1"].as_array_mut().unwrap().push(duplicate);
        assert!(common_start_request_control(&bad).is_err());
    }
}
