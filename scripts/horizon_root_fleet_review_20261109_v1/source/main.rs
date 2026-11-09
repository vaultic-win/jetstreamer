#![recursion_limit = "512"]
//! Metadata-only Root review; never native Frame, full Reader, admission or release authority.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
mod memory_target;
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-root-fleet-operational-review-tools-20261109-v4/review";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Type,Job";
fn need(ok: bool, why: &str) -> R<()> { if ok { Ok(()) } else { Err(why.into()) } }
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> { v[k].as_str().ok_or_else(|| format!("missing string {k}").into()) }
fn n(v: &Value, k: &str) -> R<u64> { v[k].as_u64().ok_or_else(|| format!("missing integer {k}").into()) }
fn sha(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn now() -> R<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }
fn ident(m: &fs::Metadata) -> Value { json!([m.dev(),m.ino(),m.mode(),m.uid(),m.gid(),m.nlink(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec()]) }
fn raw(path: &Path) -> R<Vec<u8>> {
    need(path.is_absolute() && path.canonicalize()? == path, "canonical metadata path required")?;
    let mut f = OpenOptions::new().read(true).custom_flags(NOFOLLOW|CLOEXEC).open(path)?;
    let m = f.metadata()?;
    need(m.is_file() && m.uid()==0 && m.nlink()==1 && m.mode()&0o022==0 && m.len()<=32<<20,"unsafe Root metadata")?;
    let mut b=Vec::new(); Read::by_ref(&mut f).take((32<<20)+1).read_to_end(&mut b)?;
    need(b.len() as u64==m.len() && ident(&m)==ident(&f.metadata()?) && ident(&m)==ident(&fs::symlink_metadata(path)?),"metadata changed")?;
    Ok(b)
}
fn bound(b: &Value) -> R<Value> {
    let bytes=raw(Path::new(s(b,"path")?))?;
    need(sha(&bytes)==s(b,"sha256")?,"bound metadata digest mismatch")?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn durable(path: &Path, value: &Value) -> R<()> {
    let parent=path.parent().ok_or("output parent")?;
    need(parent.is_absolute() && parent.canonicalize()?==parent,"canonical output parent required")?;
    let m=fs::symlink_metadata(parent)?;
    need(m.is_dir() && m.uid()==0 && m.mode()&0o077==0,"private Root output parent required")?;
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(NOFOLLOW|CLOEXEC).open(path)?;
    serde_json::to_writer_pretty(&mut f,value)?; f.write_all(b"\n")?; f.sync_all()?; File::open(parent)?.sync_all()?; Ok(())
}
fn command(args: &[&str], cap: usize) -> R<String> {
    let out=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(args).output()?;
    need(out.status.success() && out.stderr.is_empty() && out.stdout.len()<=cap,"systemd metadata capture failed")?;
    Ok(String::from_utf8(out.stdout)?)
}
fn unit_name(name: &str) -> R<()> {
    need(!name.starts_with('-') && (name.ends_with(".service") || name.ends_with(".timer")) && name.bytes().all(|b|(33..127).contains(&b)),"invalid unit name")
}
fn native(name: &str) -> R<Value> {
    unit_name(name)?;
    let text=command(&["show",name,"--no-pager","-p",FIELDS],65536)?;
    let mut v=serde_json::Map::new();
    for line in text.lines() { let(k,x)=line.split_once('=').ok_or("native delimiter")?; need(v.insert(k.into(),json!(x)).is_none(),"duplicate native property")?; }
    for key in ["Id","LoadState","ActiveState","SubState","InvocationID"] { need(v.get(key).is_some_and(Value::is_string),"incomplete native metadata")?; }
    Ok(Value::Object(v))
}
fn discover() -> R<BTreeSet<String>> {
    let text=command(&["list-units","--all","--plain","--no-legend","--no-pager","--type=service","--type=timer"],16<<20)?;
    let mut out=BTreeSet::new();
    for line in text.lines() {
        let name=line.split_whitespace().next().ok_or("empty loaded unit row")?;
        if name.contains("horizon") || name.contains("epoch") || name.contains("root-sweep") { unit_name(name)?; need(out.insert(name.into()),"duplicate loaded unit")?; }
    }
    Ok(out)
}
fn live(v: &Value) -> bool { v["ActiveState"]=="active" && v["SubState"]=="running" && v["MainPID"].as_str().is_some_and(|x|x.parse::<u64>().is_ok_and(|p|p>0)) }
fn owner_matches(actual: &Value, expected: &Value) -> R<()> {
    need(live(actual) && actual["NRestarts"]=="0" && actual["ControlPID"]=="0","owner not stable running")?;
    for (native_key,plan_key) in [("Id","unit"),("InvocationID","invocation_id"),("MainPID","main_pid")] { need(actual[native_key]==expected[plan_key],"owner identity mismatch")?; }
    Ok(())
}
fn potential_replay_claim(name: &str) -> bool { name.ends_with(".service") && (name.starts_with("horizon-qualify-") || name.starts_with("horizon-extract") || name.starts_with("jetstreamer-root-sweep-") || (name.contains("epoch") && name.contains("controller"))) }
fn full_epochs(rows: &[Value]) -> R<()> {
    need(rows.len()==100 && rows.iter().enumerate().all(|(i,row)| row["epoch"]==json!(101+i)),"complete ordered 101–200 census required")
}
fn wire(v: &Value, epoch: u64, sampled: &str) -> R<()> {
    let obj=v.as_object().ok_or("status object")?;
    let expected=BTreeSet::from(["epoch","jet_size_bytes","elapsed_execution_millis","estimated_remaining_millis","sampled_at_utc","phase"]);
    need(obj.keys().map(String::as_str).collect::<BTreeSet<_>>()==expected,"status exact shape")?;
    for k in ["epoch","jet_size_bytes","elapsed_execution_millis","estimated_remaining_millis"] { n(v,k)?; }
    need(n(v,"epoch")?==epoch && n(v,"estimated_remaining_millis")?>0 && s(v,"sampled_at_utc")?==sampled && matches!(s(v,"phase")?,"replay"|"verification"|"upload"|"readback"),"status epoch/phase/estimate mismatch")
}
fn statuses(audit: &Value, observer_binding: &Value) -> R<BTreeMap<u64,(Value,Value)>> {
    need(audit["schema"]=="horizon-range-status-event-correction-v1" && audit["first_epoch"]==101 && audit["last_epoch"]==200 && audit["authenticated_inventory_complete"]==true && audit["observer"]==*observer_binding && audit["archive_mutations"]==false && audit["sidecar_mutations"]==false,"status audit contract")?;
    need(audit["unresolved_status_incidents"].as_array().is_some_and(Vec::is_empty),"unresolved status incidents")?;
    let mut out=BTreeMap::new();
    for outcome in audit["outcomes"].as_array().ok_or("status outcomes")? {
        let e=n(outcome,"epoch")?; let pr=bound(&outcome["receipt"])?;
        need((101..=200).contains(&e) && outcome["outcome"]=="refreshed-authenticated-readback" && pr["schema"]=="horizon-status-only-correction-v1" && pr["authenticated_readback"]==true && pr["epoch"]==e && pr["owner_evidence"]["current_operator"]=="/root" && pr["observer"]==*observer_binding,"authenticated status owner binding")?;
        wire(&pr["after_status"],e,s(audit,"sampled_at_utc")?)?;
        let mut body=serde_json::to_vec(&pr["after_status"])?; body.push(b'\n');
        need(pr["after_sha256"]==sha(&body) && !s(&pr,"after_etag")?.is_empty() && pr["key"]==format!("epoch-{e}.epoch-status.json"),"authenticated status body digest/key")?;
        need(out.insert(e,(pr,outcome["receipt"].clone())).is_none(),"duplicate status outcome")?;
    }
    let keys=audit["status_keys"].as_object().ok_or("status key census")?.keys().map(|x|x.parse::<u64>()).collect::<Result<BTreeSet<_>,_>>()?;
    need(keys==out.keys().copied().collect(),"status key/outcome census mismatch")?;
    Ok(out)
}
fn inventory(v: &Value) -> R<BTreeSet<u64>> {
    need(v["schema"]=="jetstreamer-horizon-r2-inventory-v1" && v["first_epoch"]==101 && v["last_epoch"]==200 && v["requested_epochs"]==100 && v["anomalies"]==0 && v["archive_only"]==0,"inventory contract")?;
    let entries=v["entries"].as_array().ok_or("inventory entries")?; full_epochs(entries)?;
    let mut ready=BTreeSet::new();
    for row in entries {
        let e=n(row,"epoch")?;
        match s(row,"state")? {
            "ready-pair" => { need(n(row,"archive_length")?>0 && row["archive_metadata_sha256"]==row["sidecar_sha256"] && s(row,"sidecar_sha256")?.len()==64,"ready pair inventory evidence")?; ready.insert(e); },
            "missing" => { need(row["archive_length"].is_null() && row["sidecar_sha256"].is_null(),"missing inventory anomaly")?; },
            _ => return Err("unaccepted inventory state".into()),
        }
    }
    need(n(v,"ready_pairs")?==ready.len() as u64 && n(v,"missing")?==100-ready.len() as u64,"inventory counts mismatch")?;
    Ok(ready)
}
fn owner_observation(row: &Value, expected: &Value) -> R<()> {
    need(row["range"].as_str().and_then(|x|x.parse::<u64>().ok())==Some(n(expected,"epoch")?) && row["invocation_binding_stable"]==true,"observer owner/range mismatch")?;
    for role in ["producer_before","producer_after","controller_before","controller_after"] {
        need(row[role]["unit"]==expected["unit"] && row[role]["invocation_id"]==expected["invocation_id"] && row[role]["main_pid"].as_u64().is_some_and(|p|expected["main_pid"].as_str().and_then(|x|x.parse::<u64>().ok())==Some(p)) && row[role]["active_state"]=="active" && row[role]["sub_state"]=="running" && row[role]["restarts"]==0,"observer owner changed")?;
    }
    need(row["useful_work"]["matching_markers"].as_u64().is_some_and(|x|x>0) && row["useful_work"]["last"]["transactions"].as_u64().is_some_and(|x|x>0),"actual useful replay required")
}
fn selected_operating_count(previous: u64, point: &Value) -> R<u64> {
    let count=n(point,"proven_replay_count")?;
    let four=point["schema"]=="horizon-Root-expanded-standard-four-lane-operating-review-v1" && count==4 && point["whole_four_owner_window_seconds"]==1800;
    let five=point["schema"]=="horizon-Root-expanded-standard-five-lane-operating-review-v1" && count==5 && point["whole_five_owner_window_seconds"]==1800 && point["new_resource_observations"]==false;
    need((four||five) && point["owner"]=="/root" && point["primary_thread"]=="01a1af2a-9ce8-76a2-8939-b2112bd38f53" && point["explicit_Root_operating_point_review"]==true && point["replay_admission_authorized"]==false && count>=previous && count<=previous.checked_add(1).ok_or("count overflow")? && point["full_original_owner_and_worker_sets_unchanged"]==true && point["hard_memory_limit_and_OOM_delta_zero"]==true,"qualified explicit four/five-lane operating review required")?;
    Ok(count)
}
fn clean_five_window(current:&Value, previous:&Value, complete_data:u64) -> R<()> {
    let rows=current["replays"].as_array().ok_or("five current rows")?;
    need(rows.len()==5 && previous["replays"].as_array().is_some_and(|r|r.len()==5) && observer_owner_signatures(current)?==observer_owner_signatures(previous)?,"exact matching whole-five owner window required")?;
    need(current["cadence"]["routine_minimum_interval_enforced"]==true && current["cadence"]["observed_interval_seconds"]==1800 && n(&current["filesystem"],"conservative_available_bytes")?>=complete_data,"whole-five routine cadence or complete DATA floor failed")?;
    let pressure=&current["host_global_pressure"]["cross_sample"];
    need(pressure["status"]=="observed","whole-five host pressure missing")?;
    let elapsed=n(pressure,"elapsed_millis")?.checked_mul(1000).ok_or("pressure elapsed overflow")?;
    need(elapsed>0 && n(&pressure["counter_delta_usec"],"memory.full_total_usec")?<=elapsed/200,"host full memory pressure exceeds conservative0.5percent operating review bound")?;
    for row in rows {
        let work=&row["useful_work"];need(row["invocation_binding_stable"]==true && work["counter_resets"]==0 && work["sufficient_for_rates"]==true && work["transaction_delta"].as_u64().is_some_and(|v|v>0),"whole-five useful transaction window missing/reset")?;
        let delta=&row["cross_sample"]["producer_cgroup_counter_delta"];
        for key in ["memory_events.max","memory_events.oom","memory_events.oom_kill","memory_events.oom_group_kill"] {need(delta[key]==0,"whole-five hard memory/OOM event")?;}
        need(row["worker_after"]["matching_workers"]==1 && row["worker_after"]["executable_beneath_bound_scratch"]==true && n(&row["worker_after"],"vmas")?<3_500_000,"whole-five worker/VMA stop mismatch")?;
    }
    Ok(())
}
fn current_memory_target(o: &Value, supplemental: &[Value], policy: &Value) -> R<Value> {
    let ordinary=o["replays"].as_array().ok_or("current memory observation rows")?;
    let private=o["diagnostic_replays"].as_array().ok_or("current diagnostic observation rows")?.iter().filter_map(|row| {
        if row["status"]=="observed" {Some(&row["observation"])} else if row.get("status").is_none() {Some(row)} else {None}
    }).filter(|row|row["producer_after"]["active_state"]=="active" && row["producer_after"]["sub_state"]=="running").count();
    need(policy["schema"]=="horizon-Root-coordinated-memory-target-policy-v1" && policy["century"]==100 && n(policy,"expected_observed_production_replays")?==ordinary.len() as u64 && n(policy,"expected_supplemental_production_replays")?==supplemental.len() as u64 && n(policy,"expected_observed_private_replays")?==private as u64,"plan-bound current memory owner census differs")?;
    let unobserved=policy["unobserved_active_resource_owners"].as_array().ok_or("explicit unobserved resource-owner census required")?;
    for owner in unobserved {unit_name(owner.as_str().ok_or("unobserved resource owner unit")?)?;}
    let mut report=if !supplemental.is_empty() {
        json!({"valid":false,"target_percent":90,"limiting_gate":"Live supplemental replay owners are absent from this coordinated RSS sample.","missing_supplemental_epochs":supplemental.iter().map(|row|row["epoch"].clone()).collect::<Vec<_>>(),"admission_authorized":false})
    } else if !unobserved.is_empty() {
        json!({"valid":false,"target_percent":90,"limiting_gate":"Root's explicit active resource-owner census includes owners without supported same-sample telemetry.","unobserved_active_resource_owners":unobserved,"admission_authorized":false})
    } else {
        memory_target::report(o,ordinary.len(),private)
    };
    report["sampled_at_utc"]=o["recorded_at_utc"].clone();
    report["observed_production_replays"]=json!(ordinary.len());
    report["supplemental_production_replays"]=json!(supplemental.len());
    report["observed_private_replays"]=json!(private);
    report["all_live_production_replays_in_current_observer"]=json!(supplemental.is_empty());
    report["native_Frame_or_full_Reader_acceptance_claimed"]=json!(false);
    report["admission_authorized"]=json!(false);
    Ok(report)
}
fn observer_owner_signatures(o: &Value) -> R<BTreeSet<String>> {
    let mut owners=BTreeSet::new();
    for row in o["replays"].as_array().ok_or("window replay rows")? {
        let value=json!([row["range"],row["producer_after"]["unit"],row["producer_after"]["invocation_id"],row["producer_after"]["main_pid"],row["controller_after"]["unit"],row["controller_after"]["invocation_id"],row["controller_after"]["main_pid"],row["worker_after"]["pid"],row["worker_after"]["executable"],row["scratch_path"]]);
        need(owners.insert(serde_json::to_string(&value)?),"duplicate expanded-window owner signature")?;
    }
    Ok(owners)
}
fn expanded_window_metadata(current: &Value, previous: &Value, supplemental: &[Value], binding: &Value) -> R<Value> {
    let same=observer_owner_signatures(current)?==observer_owner_signatures(previous)?;
    let reason=if !supplemental.is_empty() {
        "Live supplemental owners are absent from the current coordinated sample; a complete expanded owner window is still required."
    } else if !same {
        "Every live production replay is present in the current coordinated sample, but predecessor owner signatures differ; require a later matching expanded window."
    } else {
        "Current and predecessor production owner signatures match. This metadata comparison does not qualify the full window or replace explicit current guard, floor and operating-point review."
    };
    Ok(json!({"qualified":false,"previous_observer":binding,"all_live_production_replays_in_current_observer":supplemental.is_empty(),"predecessor_production_owner_signatures_match":same,"supplemental_replay_count":supplemental.len(),"routine_interval_seconds":current["cadence"]["observed_interval_seconds"],"requires_explicit_operating_point_review":true,"reason":reason,"replay_admission_authorized":false}))
}
fn run() -> R<()> {
    let argv=std::env::args().collect::<Vec<_>>();
    need(argv.len()==7 && argv[1]=="review" && argv[3]=="--plan-sha256" && argv[5]=="--self-sha256","review PLAN --plan-sha256 SHA --self-sha256 SHA")?;
    let own=fs::metadata("/proc/self")?; need(own.uid()==0,"Root execution required")?;
    let self_path=fs::read_link("/proc/self/exe")?; need(self_path==Path::new(IMAGE),"normal sealed runtime image required")?;
    need(sha(&raw(Path::new("/proc/self/exe").canonicalize()?.as_path())?)==argv[6],"self image digest mismatch")?;
    let plan_raw=raw(Path::new(&argv[2]))?; need(sha(&plan_raw)==argv[4],"plan digest mismatch")?;
    let plan:Value=serde_json::from_slice(&plan_raw)?;
    need(plan["schema"]=="horizon-Root-complete-fleet-review-plan-v1" && plan["owner"]=="/root" && plan["primary_thread"]=="01a1af2a-9ce8-76a2-8939-b2112bd38f53","Root review plan owner")?;
    let prev=bound(&plan["previous_review"])?; let obs=bound(&plan["observer"])?; let audit=bound(&plan["status_audit"])?; let inv=bound(&plan["inventory"])?; let resource=bound(&plan["complete_DATA_authority"])?; let timer=bound(&plan["next_observer_receipt"])?;
    need(prev["schema"]=="horizon-Root-complete-fleet-operational-review-v1" && prev["owner"]=="/root" && prev["primary_thread"]==plan["primary_thread"],"predecessor Root authority")?;
    need(obs["schema"]=="jetstreamer-horizon-live-resource-sample-v2" && obs["cadence"]["routine_minimum_interval_enforced"]==true && obs["cadence"]["observed_interval_seconds"].as_u64().is_some_and(|x|x>=1800) && obs["recorded_at_utc"]==plan["sampled_at_utc"] && s(&obs,"recorded_at_utc")?>s(&prev,"sampled_at_utc")?,"coordinated observer cadence")?;
    need(timer["next_utc"]==plan["next_observer_utc"] && obs["cadence"]["next_routine_observation_not_before_utc"]==plan["next_observer_utc"],"next sole observer binding")?;
    need(resource["owner"]=="/root" && resource["primary_thread"]==plan["primary_thread"] && resource["complete_DATA_bytes"]==plan["complete_DATA_bytes"] && resource["complete_projected_memory_bytes"]==plan["complete_projected_memory_bytes"] && resource["normal_pool_bytes"]==plan["normal_pool_bytes"],"complete retained accounting authority")?;
    let ready=inventory(&inv)?; let status=statuses(&audit,&plan["observer"])?;
    need(n(&inv,"ready_pairs")?==n(&plan,"expected_ready_pairs")? && n(&inv,"missing")?==n(&plan,"expected_missing")? && status.len() as u64==n(&plan,"expected_status_count")? && status.keys().all(|e|!ready.contains(e)),"inventory/status expectation changed")?;
    let rows=prev["epochs"].as_array().ok_or("previous epochs")?; full_epochs(rows)?;
    let expected=plan["replays"].as_array().ok_or("replay plan")?;
    let observations=obs["replays"].as_array().ok_or("replay observations")?;
    need(expected.len()==observations.len() && !expected.is_empty(),"complete replay set")?;
    let mut owner_before=BTreeMap::new(); let mut epochs=BTreeSet::new();
    for e in expected {
        let epoch=n(e,"epoch")?; need(epochs.insert(epoch) && !ready.contains(&epoch),"duplicate/ready replay claim")?;
        let matches=observations.iter().filter(|r|r["range"].as_str().and_then(|x|x.parse::<u64>().ok())==Some(epoch)).collect::<Vec<_>>(); need(matches.len()==1,"exact replay observation required")?; owner_observation(matches[0],e)?;
        let v=native(s(e,"unit")?)?; owner_matches(&v,e)?;
        need(owner_before.insert(s(e,"unit")?.to_string(),v).is_none(),"duplicate replay unit")?;
        let pr=&status.get(&epoch).ok_or("replay status missing")?.0;
        need(pr["after_status"]["phase"]=="replay" && pr["owner_evidence"]["actual_producer"]["InvocationID"]==e["invocation_id"],"replay status owner mismatch")?;
    }
    let supplemental=plan["supplemental_live_replays"].as_array().ok_or("explicit supplemental replay census required")?;
    let mut supplemental_events=BTreeMap::new();
    for e in supplemental {
        let epoch=n(e,"epoch")?;need(epochs.insert(epoch) && !ready.contains(&epoch) && !observations.iter().any(|r|r["range"].as_str().and_then(|x|x.parse::<u64>().ok())==Some(epoch)),"supplement overlaps observer or ready pair")?;
        let event=bound(&e["source_phase_event"])?;let admission=bound(&e["admission"])?;let guard=bound(&e["first_guard"])?;
        need(event["schema"]=="horizon-singleton-first-target-transaction-phase-event-v1" && event["latest_target_progress"]["transactions"].as_u64().is_some_and(|x|x>0) && event["source_log"]["stdout_append_binding_verified"]==true && event["no_new_resource_sample"]==true && event["resource_admission_authorized"]==false && admission["owner"]=="/root" && admission["primary_thread"]==plan["primary_thread"] && e["admission"]==plan["complete_DATA_authority"] && guard["producer_invocation_id"]==e["invocation_id"] && guard["producer_stop_enabled"]==true && guard["trip_reason"].is_null() && guard["root_physical_observation_error"].is_null() && guard["worker_observation_error"].is_null(),"supplement genuine transaction/admission/guard proof")?;
        let actual=native(s(e,"unit")?)?;owner_matches(&actual,e)?;
        for(k,v)in event["producer_after"].as_object().ok_or("supplement event owner")? {need(actual[k]==*v,"supplement owner changed since phase event")?;}
        let pr=&status.get(&epoch).ok_or("supplement status missing")?.0;need(pr["after_status"]["phase"]=="replay" && pr["owner_evidence"]["actual_producer"]["InvocationID"]==e["invocation_id"],"supplement replay status owner mismatch")?;
        need(owner_before.insert(s(e,"unit")?.into(),actual).is_none(),"duplicate supplement owner")?;supplemental_events.insert(epoch,event);
    }
    let controls=plan["stable_non_replay_owners"].as_array().ok_or("non-replay stable owners")?;
    let mut stable_controls=BTreeMap::new();
    for e in controls { let v=native(s(e,"unit")?)?; owner_matches(&v,e)?; need(stable_controls.insert(s(e,"unit")?.into(),v).is_none(),"duplicate control owner")?; }
    let discovered=discover()?; let mut names=discovered.clone();
    for name in prev["metadata_unit_census"].as_object().ok_or("complete prior unit census")?.keys() { unit_name(name)?; names.insert(name.clone()); }
    names.extend(owner_before.keys().cloned()); names.extend(stable_controls.keys().cloned());
    let mut census=BTreeMap::new(); let mut background=Vec::new();
    for name in &names {
        let v=native(name)?;
        if live(&v) && potential_replay_claim(name) { need(owner_before.contains_key(name)||stable_controls.contains_key(name),"new running producer/controller claim requires explicit Root handoff")?; }
        if live(&v) && !owner_before.contains_key(name) { background.push(json!({"requested_unit":name,"unit":v,"not_counted_as_replay":true})); }
        census.insert(name.clone(),v);
    }
    need(discover()?.is_subset(&names),"new loaded Horizon unit appeared during census")?;
    let mut active=Vec::new(); let mut new_rows=Vec::new(); let mut backlog=Vec::new();
    for old in rows {
        let mut row=old.clone(); let e=n(old,"epoch")?;
        row["previous_operational_state"]=old["state"].clone();
        if ready.contains(&e) { row["state"]=json!("remote-ready"); row["status"]=Value::Null; row["status_publication"]=Value::Null; }
        else if epochs.contains(&e) { row["state"]=json!("live-replay"); row["next_action"]=json!("Preserve healthy original producer and genuine protective guard. At genuine terminal capture committed singleton output, then dispatch full/current-plugin verification, canonical import and the existing uploader; no publication or retirement gate is waived."); }
        else { need(matches!(s(&row,"state")?,"post-replay-pipeline"|"staged-admissible"|"blocked-qualification"|"failed-needs-repair"|"not-yet-staged"),"non-running state requires explicit transition")?; }
        if let Some((pr,binding))=status.get(&e) {
            row["previous_status_publication"]=old["status_publication"].clone(); row["status_publication"]=binding.clone();
            row["status"]=json!({"classification":if epochs.contains(&e){"authenticated-live-replay"}else{"authenticated-active-Root-repair-or-preparation"},"current_eta_valid":true,"owner_binding_matches":true,"sample_matches_observer":false,"status_sample_at_or_after_observer":s(&pr["after_status"],"sampled_at_utc")?>=s(&obs,"recorded_at_utc")?,"payload":pr["after_status"],"etag":pr["after_etag"],"sha256":pr["after_sha256"],"freshness_basis":"Bound authenticated readback at audit timestamp; no additional remote lookup or resource observation","production_claim_eligible":epochs.contains(&e)});
            row["current_operator"]=json!("/root"); row["current_task"]=pr["owner_evidence"]["current_task"].clone();
        }
        if let Some(action)=plan["next_actions_by_epoch"].get(e.to_string().as_str()) { need(action.as_str().is_some_and(|x|!x.is_empty()) && !ready.contains(&e),"invalid Root next action override")?; row["next_action"]=action.clone(); }
        if epochs.contains(&e) {
            if let Some(expected_owner)=expected.iter().find(|x|x["epoch"]==e) {
                let observation=observations.iter().find(|x|x["range"].as_str().and_then(|x|x.parse::<u64>().ok())==Some(e)).ok_or("owner observation")?;
                active.push(json!({"epoch":e,"phase":"replay","unit":owner_before[s(expected_owner,"unit")?],"observer":plan["observer"],"progress":observation["useful_work"],"scratch_path":observation["scratch_path"],"status_publication":row["status_publication"],"in_current_observer":true}));
            } else {
                let owner=supplemental.iter().find(|x|x["epoch"]==e).ok_or("supplement owner")?;let event=&supplemental_events[&e];
                active.push(json!({"epoch":e,"phase":"replay","unit":owner_before[s(owner,"unit")?],"source_phase_event":owner["source_phase_event"],"latest_target_progress":event["latest_target_progress"],"scratch_path":owner["scratch_path"],"status_publication":row["status_publication"],"in_current_observer":false,"measured_rate_claimed":false}));
            }
        }
        if !ready.contains(&e) { backlog.push(json!({"epoch":e,"state":row["state"],"next_action":row["next_action"],"current_task":row["current_task"],"gate_evidence":row["gate_evidence"],"last_reconciled_at_utc":obs["recorded_at_utc"],"repair_closed":false,"prior_history_preserved_by":plan["previous_review"]})); }
        new_rows.push(row);
    }
    for(name,before)in owner_before.iter().chain(stable_controls.iter()) { need(native(name)?==*before,"live owner changed during review")?; }
    for key in ["previous_review","observer","status_audit","inventory","complete_DATA_authority","next_observer_receipt"] { bound(&plan[key])?; }
    for (_,binding) in status.values() { bound(binding)?; }
    let previous_count=n(&prev,"proven_replay_count")?;
    let point=bound(&plan["operating_point"])?;let selected_count=selected_operating_count(previous_count,&point)?;
    let point_now=bound(&point["observer"])?;let point_before=bound(&point["predecessor_observer"])?;
    need(point_now["cadence"]["previous_sample_sha256"]==point["predecessor_observer"]["sha256"] && point_now["cadence"]["observed_interval_seconds"]==1800,"operating window predecessor mismatch")?;
    let point_owners=point["current_native_producers"].as_object().ok_or("operating owner census")?;need(point_owners.len() as u64==selected_count,"operating owner census count")?;
    for(epoch,unit)in point_owners {let e=epoch.parse::<u64>()?;let expected=json!({"epoch":e,"unit":unit["Id"],"invocation_id":unit["InvocationID"],"main_pid":unit["MainPID"]});for sample in [&point_before,&point_now] {let r=sample["replays"].as_array().ok_or("operating rows")?.iter().find(|x|x["range"]==epoch.as_str()).ok_or("operating row absent")?;owner_observation(r,&expected)?;}}
    for g in point["fresh_genuine_guards"].as_array().ok_or("operating guard census")? {let sample=bound(&g["receipt"])?;need(sample["trip_reason"].is_null() && sample["producer_stop_enabled"]==true && sample["guard_sha256"]=="35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc","operating guard proof changed")?;}
    if selected_count==5 {
        let authority=bound(&point["complete_resource_authority"])?;
        clean_five_window(&point_now,&point_before,n(&authority,"complete_DATA_bytes")?)?;
        let guards=point["fresh_genuine_guards"].as_array().ok_or("five genuine guards")?;
        need(guards.len()==5,"whole-five genuine guard census")?;
        let mut epochs=BTreeSet::new();
        for guard in guards {let epoch=n(guard,"epoch")?;need(epochs.insert(epoch),"duplicate guard epoch")?;let owner=point_owners.get(&epoch.to_string()).ok_or("guard owner absent")?;let receipt=bound(&guard["receipt"])?;need(receipt["producer_invocation_id"]==owner["InvocationID"] && receipt["root_physical_observation_error"].is_null() && receipt["worker_observation_error"].is_null() && guard["timer"]["ActiveState"]=="active" && guard["timer"]["SubState"]=="waiting" && guard["native"]["Result"]=="success" && guard["native"]["ExecMainStatus"]=="0" && guard["native"]["MainPID"]=="0" && guard["native"]["ControlPID"]=="0","whole-five genuine guard/timer proof")?;}
    }
    need(plan["proven_replay_count"]==selected_count,"explicit operating review differs from plan")?;
    let previous_observer_binding=json!({"path":obs["cadence"]["previous_sample"],"sha256":obs["cadence"]["previous_sample_sha256"]});
    let previous_observer=bound(&previous_observer_binding)?;
    need(previous_observer["recorded_at_utc"]==obs["cadence"]["previous_sample_recorded_at_utc"],"current predecessor observation timestamp mismatch")?;
    let mut memory=current_memory_target(&obs,supplemental,&plan["memory_target_policy"])?;
    memory["observer"]=plan["observer"].clone();memory["policy"]=plan["memory_target_policy"].clone();
    let expanded_window=expanded_window_metadata(&obs,&previous_observer,supplemental,&previous_observer_binding)?;
    let report=json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":plan["primary_thread"],"sampled_at_utc":obs["recorded_at_utc"],"recorded_unix_seconds":now()?,"previous_Root_operational_review":plan["previous_review"],"previous_qualified_fleet":prev["previous_qualified_fleet"],"observer":plan["observer"],"authenticated_inventory":plan["inventory"],"authenticated_status_audit":plan["status_audit"],"complete_DATA_authority":plan["complete_DATA_authority"],"complete_DATA_bytes":plan["complete_DATA_bytes"],"complete_projected_memory_bytes":plan["complete_projected_memory_bytes"],"normal_pool_bytes":plan["normal_pool_bytes"],"same_sample_conservative_free_DATA_bytes":obs["filesystem"]["conservative_available_bytes"],"ready_pairs":ready.len(),"remaining_epochs":100-ready.len(),"live_replay_count":active.len(),"proven_replay_count":selected_count,"operating_point":plan["operating_point"],"current_memory_selected_target":memory,"last_qualified_memory_selected_target":if memory["valid"]==true {memory["desired_lanes"].clone()} else {prev["last_qualified_memory_selected_target"].clone()},"previous_qualified_memory_selected_target":prev["last_qualified_memory_selected_target"],"expanded_fleet_window":expanded_window,"next_capacity_action":plan["next_capacity_action"],"next_observer_utc":plan["next_observer_utc"],"next_observer_receipt":plan["next_observer_receipt"],"actual_executing_replays":active,"metadata_unit_census":census,"currently_running_background_control_services":background,"stable_non_replay_owners":stable_controls,"epochs":new_rows,"open_repair_backlog":backlog,"all15_active_status_reports_authenticated_readback":status.len()>=15,"all_active_status_reports_authenticated_readback":status.len() as u64==n(&plan,"expected_status_count")?,"authenticated_status_count":status.len(),"current_native_Frame_and_full_reader_acceptance_pending":true,"review_is_not_a_native_Frame_or_admission_receipt":true,"resource_credit_bytes":0,"holding_bytes_credited":0,"holding_prefix":"node_02/","remote_mutations":false,"replay_launch_authorized":false,"producer_mutations":false,"new_resource_observations":false});
    durable(Path::new(s(&plan,"output")?),&report)?;
    println!("{}",json!({"output":plan["output"],"ready_pairs":ready.len(),"remaining_epochs":100-ready.len(),"live_replay_count":epochs.len(),"authenticated_status_count":status.len(),"new_resource_observations":false,"remote_mutations":false,"resource_credit_bytes":0})); Ok(())
}
fn main() { if let Err(e)=run() { eprintln!("{e}"); std::process::exit(1); } }

#[cfg(test)]
mod tests {
    use super::*;
    fn status() -> Value { json!({"epoch":169,"jet_size_bytes":1,"elapsed_execution_millis":2,"estimated_remaining_millis":3,"sampled_at_utc":"2026-11-09T20:33:36Z","phase":"replay"}) }
    #[test] fn complete_range_rejects_missing_duplicate_and_reordered_rows() { let v=(101..=200).map(|e|json!({"epoch":e})).collect::<Vec<_>>(); assert!(full_epochs(&v).is_ok()); let mut bad=v.clone();bad.remove(4);assert!(full_epochs(&bad).is_err());let mut bad=v;bad.swap(3,4);assert!(full_epochs(&bad).is_err()); }
    #[test] fn exact_status_shape_and_positive_eta_are_required() { let v=status();assert!(wire(&v,169,"2026-11-09T20:33:36Z").is_ok());let mut bad=v.clone();bad["extra"]=json!(1);assert!(wire(&bad,169,"2026-11-09T20:33:36Z").is_err());let mut bad=v;bad["estimated_remaining_millis"]=json!(0);assert!(wire(&bad,169,"2026-11-09T20:33:36Z").is_err()); }
    #[test] fn status_rejects_unsupported_phase_wrong_epoch_and_timestamp() { let mut v=status();v["phase"]=json!("qualification");assert!(wire(&v,169,"2026-11-09T20:33:36Z").is_err());assert!(wire(&status(),170,"2026-11-09T20:33:36Z").is_err());assert!(wire(&status(),169,"2026-11-09T20:34:36Z").is_err()); }
    #[test] fn active_owner_requires_exact_iid_pid_and_zero_restarts() { let expected=json!({"unit":"x.service","invocation_id":"abc","main_pid":"12"});let mut actual=json!({"Id":"x.service","InvocationID":"abc","MainPID":"12","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running"});assert!(owner_matches(&actual,&expected).is_ok());actual["InvocationID"]=json!("replacement");assert!(owner_matches(&actual,&expected).is_err());actual["InvocationID"]=json!("abc");actual["NRestarts"]=json!("1");assert!(owner_matches(&actual,&expected).is_err()); }
    #[test] fn new_claim_predicate_does_not_count_guards_or_control_watchers() { assert!(potential_replay_claim("horizon-qualify-170-standard.service"));assert!(potential_replay_claim("jetstreamer-epoch199-controller.service"));assert!(!potential_replay_claim("horizon-guard-169-standard.service"));assert!(!potential_replay_claim("horizon-r2-progressive.service")); }
    #[test] fn missing_inventory_and_anomalies_fail_closed() { let mut v=json!({"schema":"jetstreamer-horizon-r2-inventory-v1","first_epoch":101,"last_epoch":200,"requested_epochs":100,"anomalies":0,"archive_only":0,"ready_pairs":0,"missing":100,"entries":(101..=200).map(|e|json!({"epoch":e,"state":"missing","archive_length":null,"sidecar_sha256":null})).collect::<Vec<_>>()});assert!(inventory(&v).is_ok());v["anomalies"]=json!(1);assert!(inventory(&v).is_err()); }
    #[test] fn replay_binding_rejects_warmup_without_target_transactions() { let expected=json!({"epoch":169,"unit":"x.service","invocation_id":"a","main_pid":"12"});let role=json!({"unit":"x.service","invocation_id":"a","main_pid":12,"active_state":"active","sub_state":"running","restarts":0});let mut row=json!({"range":"169","invocation_binding_stable":true,"producer_before":role,"producer_after":role,"controller_before":role,"controller_after":role,"useful_work":{"matching_markers":3,"last":{"transactions":1}}});assert!(owner_observation(&row,&expected).is_ok());row["useful_work"]["last"]["transactions"]=json!(0);assert!(owner_observation(&row,&expected).is_err()); }
    #[test] fn unit_names_reject_argument_injection_and_nonunits() { assert!(unit_name("horizon-guard169.timer").is_ok());assert!(unit_name("--help").is_err());assert!(unit_name("bad unit.service").is_err());assert!(unit_name("x.target").is_err()); }
    fn five_owner_memory_fixture() -> Value {
        let mut rows=Vec::new();let mut processes=Vec::new();
        for (pid,epoch) in (1u64..=5).zip(166u64..=170) {
            let process=json!({"pid":pid,"start_ticks":10,"rss_bytes":100*1024});processes.push(process.clone());
            let unit=json!({"unit":format!("horizon-qualify-{epoch}.service"),"invocation_id":format!("{epoch:032x}"),"main_pid":pid,"restarts":0,"active_state":"active","sub_state":"running","rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":100*1024,"processes":[process]}});
            rows.push(json!({"range":epoch.to_string(),"invocation_binding_stable":true,"controller_before":unit,"producer_before":unit,"controller_after":unit,"producer_after":unit,"scratch_path":format!("/private/{epoch}/scratch"),"worker_after":{"pid":pid,"executable":format!("/private/{epoch}/worker")}}));
        }
        processes.push(json!({"pid":6,"start_ticks":20,"rss_bytes":100*1024}));
        json!({"recorded_at_utc":"2026-11-09T22:30:22Z","cadence":{"observed_interval_seconds":1800},"replays":rows,"diagnostic_replays":[],"host_memory":{"total_kib":1000,"conservative_available_kib":900},"host_resident_memory":{"after":{"status":"observed","rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":600*1024,"processes":processes},"kernel_components_bytes":{"Slab":0,"KernelStack":0,"PageTables":0,"Percpu":0}}},"lane_rss_history":{"100":{"maximum_observed_lane_rss_bytes":100*1024,"reservation_ceiling_bytes":150*1024}}})
    }
    fn memory_policy(observed:usize,supplemental:usize) -> Value {json!({"schema":"horizon-Root-coordinated-memory-target-policy-v1","century":100,"expected_observed_production_replays":observed,"expected_supplemental_production_replays":supplemental,"expected_observed_private_replays":0,"unobserved_active_resource_owners":[]})}
    #[test] fn full_five_sample_computes_current_target_without_promoting_point() {
        let o=five_owner_memory_fixture();let r=current_memory_target(&o,&[],&memory_policy(5,0)).unwrap();
        assert_eq!(r["valid"],true,"{r}");assert_eq!(r["desired_lanes"],8);assert_eq!(r["executing_lanes"],5);assert_eq!(r["aggregate_lane_rss_bytes"],500*1024);assert_eq!(r["non_lane_resident_planning_bytes"],100*1024);assert_eq!(r["admission_authorized"],false);assert_eq!(r["native_Frame_or_full_Reader_acceptance_claimed"],false);
        let w=expanded_window_metadata(&o,&o,&[],&json!({"path":"/prior","sha256":"a"})).unwrap();assert_eq!(w["qualified"],false);assert_eq!(w["predecessor_production_owner_signatures_match"],true);assert_eq!(w["requires_explicit_operating_point_review"],true);
    }
    #[test] fn supplemented_four_never_treats_unobserved_fifth_as_host_overhead() {
        let mut o=five_owner_memory_fixture();o["replays"].as_array_mut().unwrap().pop();let supplement=[json!({"epoch":170})];
        let r=current_memory_target(&o,&supplement,&memory_policy(4,1)).unwrap();assert_eq!(r["valid"],false);assert_eq!(r["missing_supplemental_epochs"],json!([170]));assert!(r.get("desired_lanes").is_none());
        let w=expanded_window_metadata(&o,&o,&supplement,&Value::Null).unwrap();assert_eq!(w["all_live_production_replays_in_current_observer"],false);assert_eq!(w["qualified"],false);
    }
    #[test] fn policy_owner_count_and_unobserved_delivery_gaps_are_explicit() {
        let o=five_owner_memory_fixture();assert!(current_memory_target(&o,&[],&memory_policy(4,0)).is_err());
        let mut policy=memory_policy(5,0);policy["unobserved_active_resource_owners"]=json!(["horizon-verifier145.service"]);let r=current_memory_target(&o,&[],&policy).unwrap();assert_eq!(r["valid"],false);assert_eq!(r["unobserved_active_resource_owners"],json!(["horizon-verifier145.service"]));assert!(r.get("desired_lanes").is_none());
    }
    #[test] fn changed_rss_pid_and_missing_host_census_return_no_target() {
        let mut o=five_owner_memory_fixture();o["replays"][4]["producer_after"]["rss"]["processes"][0]["start_ticks"]=json!(99);assert_eq!(current_memory_target(&o,&[],&memory_policy(5,0)).unwrap()["valid"],false);
        let mut o=five_owner_memory_fixture();o["host_resident_memory"]=Value::Null;assert_eq!(current_memory_target(&o,&[],&memory_policy(5,0)).unwrap()["valid"],false);
    }
    #[test] fn kernel_is_counted_once_and_disk_does_not_lower_memory_target() {
        let mut o=five_owner_memory_fixture();o["filesystem"]=json!({"conservative_available_bytes":0});o["host_resident_memory"]["after"]["kernel_components_bytes"]["Slab"]=json!(200*1024);
        let r=current_memory_target(&o,&[],&memory_policy(5,0)).unwrap();assert_eq!(r["valid"],true);assert_eq!(r["desired_lanes"],6);assert_eq!(r["kernel_resident_bytes"],200*1024);assert_eq!(r["non_lane_resident_planning_bytes"],300*1024);assert_eq!(r["disk_or_cpu_used_to_lower_desired_count"],false);
    }
    #[test] fn full_five_row_is_not_a_matching_window_after_replacement() {
        let current=five_owner_memory_fixture();let mut previous=current.clone();previous["replays"][4]["producer_after"]["invocation_id"]=json!("replacement");
        let w=expanded_window_metadata(&current,&previous,&[],&Value::Null).unwrap();assert_eq!(w["all_live_production_replays_in_current_observer"],true);assert_eq!(w["predecessor_production_owner_signatures_match"],false);assert_eq!(w["qualified"],false);
    }
    #[test] fn selected_four_point_cannot_be_promoted_by_five_live_rows() {
        let mut point=json!({"schema":"horizon-Root-expanded-standard-four-lane-operating-review-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","explicit_Root_operating_point_review":true,"replay_admission_authorized":false,"proven_replay_count":4,"whole_four_owner_window_seconds":1800,"full_original_owner_and_worker_sets_unchanged":true,"hard_memory_limit_and_OOM_delta_zero":true});
        assert_eq!(selected_operating_count(4,&point).unwrap(),4);point["proven_replay_count"]=json!(5);assert!(selected_operating_count(4,&point).is_err());
    }
    #[test] fn selected_five_needs_explicit_schema_and_cannot_jump_two_points() {
        let mut p=json!({"schema":"horizon-Root-expanded-standard-five-lane-operating-review-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","explicit_Root_operating_point_review":true,"replay_admission_authorized":false,"proven_replay_count":5,"whole_five_owner_window_seconds":1800,"new_resource_observations":false,"full_original_owner_and_worker_sets_unchanged":true,"hard_memory_limit_and_OOM_delta_zero":true});
        assert_eq!(selected_operating_count(4,&p).unwrap(),5);assert!(selected_operating_count(3,&p).is_err());p["schema"]=json!("unknown");assert!(selected_operating_count(4,&p).is_err());
    }
    fn clean_fixture()->Value {let mut o=five_owner_memory_fixture();o["cadence"]["routine_minimum_interval_enforced"]=json!(true);o["filesystem"]=json!({"conservative_available_bytes":100});o["host_global_pressure"]=json!({"cross_sample":{"status":"observed","elapsed_millis":1800000,"counter_delta_usec":{"memory.full_total_usec":0}}});for r in o["replays"].as_array_mut().unwrap(){r["useful_work"]=json!({"counter_resets":0,"sufficient_for_rates":true,"transaction_delta":1});r["cross_sample"]=json!({"producer_cgroup_counter_delta":{"memory_events.max":0,"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0}});r["worker_after"]["matching_workers"]=json!(1);r["worker_after"]["executable_beneath_bound_scratch"]=json!(true);r["worker_after"]["vmas"]=json!(100);}o}
    #[test] fn clean_five_window_rejects_pressure_hard_events_resets_and_floor_loss() {
        let o=clean_fixture();assert!(clean_five_window(&o,&o,100).is_ok());assert!(clean_five_window(&o,&o,101).is_err());let mut b=o.clone();b["replays"][0]["cross_sample"]["producer_cgroup_counter_delta"]["memory_events.oom"]=json!(1);assert!(clean_five_window(&b,&o,100).is_err());let mut b=o.clone();b["replays"][4]["useful_work"]["counter_resets"]=json!(1);assert!(clean_five_window(&b,&o,100).is_err());let mut b=o.clone();b["host_global_pressure"]["cross_sample"]["counter_delta_usec"]["memory.full_total_usec"]=json!(10_000_000);assert!(clean_five_window(&b,&o,100).is_err());
    }
    #[test] fn clean_five_window_rejects_replacement_and_vma_stop() {let o=clean_fixture();let mut b=o.clone();b["replays"][4]["worker_after"]["pid"]=json!(99);assert!(clean_five_window(&b,&o,100).is_err());let mut b=o.clone();b["replays"][0]["worker_after"]["vmas"]=json!(3_500_000);assert!(clean_five_window(&b,&o,100).is_err());}

}
