//! Exact native227 terminal event; never promotes the full epoch or starts replay.
use super::*;
use super::{singleton227 as c, singleton227_admission as admission};
pub(super) const TERMINAL_SCHEMA: &str = "jetstreamer-private-epoch227-native-input-terminal-event-v1";
pub(super) fn journal_terminal(rows: &[Value], iid: &str, pid: u64) -> Result<(bool, u64)> {
    let mut terminal = None;
    let mut child_seen = false;
    for row in rows {
        let manager = row["_PID"] == "1" && row["UNIT"] == admission::NATIVE_UNIT && row["INVOCATION_ID"] == iid;
        let child = row["_SYSTEMD_UNIT"] == admission::NATIVE_UNIT && row["_SYSTEMD_INVOCATION_ID"] == iid;
        if child { ensure!(row["_PID"].as_str().and_then(|p| p.parse::<u64>().ok()) == Some(pid), "227 native journal PID differs"); child_seen = true; }
        if !manager { continue; }
        let message = row["MESSAGE"].as_str().context("227 manager message")?;
        let success = message == format!("{}: Deactivated successfully.", admission::NATIVE_UNIT);
        let failure = message.starts_with(&format!("{}: Failed with result '", admission::NATIVE_UNIT)) && message.ends_with("'.");
        if success || failure {
            let clock = row["__REALTIME_TIMESTAMP"].as_str().context("227 terminal journal clock")?.parse::<u64>()?;
            ensure!(terminal.replace((success, clock)).is_none(), "227 duplicate terminal manager outcome");
        }
    }
    ensure!(child_seen, "227 exact child PID journal absent");
    terminal.context("227 exact PID1 terminal outcome absent")
}
fn terminal_shape(current: &Value, iid: &str, success: bool) -> Result<()> {
    ensure!(current["Id"] == admission::NATIVE_UNIT && current["MainPID"] == "0" && current["NRestarts"] == "0"
        && (current["InvocationID"] == iid || current["InvocationID"] == "")
        && matches!((current["ActiveState"].as_str(), current["SubState"].as_str()),
            (Some("inactive"),Some("dead")) | (Some("failed"),Some("failed")))
        && (!success || current["Result"] == "success"), "227 native is live, restarted, replaced or contradicts journal");
    Ok(())
}
pub(super) fn terminal_proof(proof: &Value) -> Result<(String, bool, u64)> {
    ensure!(proof["schema"] == TERMINAL_SCHEMA && proof["epoch"] == 227 && proof["unit"] == admission::NATIVE_UNIT
        && proof["resource_samples_taken"] == 0, "227 terminal scope differs");
    for key in ["replay_launch_authorized","runtime_promotion_authorized","publication_authorized","remote_mutations","r2_mutations","entry_replay"] {
        ensure!(proof[key] == false, "227 terminal event grants authority");
    }
    let origin_binding: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    let origin = bound_json(&origin_binding)?;
    let iid = origin["invocation_id"].as_str().context("227 terminal origin IID")?;
    let pid = origin["main_pid"].as_u64().context("227 terminal origin PID")?;
    ensure!(origin["schema"] == "jetstreamer-private-epoch227-native-input-running-v1" && origin["unit"] == admission::NATIVE_UNIT
        && proof["invocation_id"] == iid && proof["main_pid"] == pid, "227 terminal origin substitution");
    let journal = bound_json(&serde_json::from_value(proof["journal"].clone())?)?;
    let rows = journal.as_array().context("227 terminal journal rows")?;
    ensure!(rows.len() <= 4096, "227 terminal journal bounds");
    let (success, clock) = journal_terminal(rows, iid, pid)?;
    ensure!(proof["child_success"] == success && proof["terminal_unix_microseconds"] == clock, "227 terminal outcome differs");
    terminal_shape(&proof["terminal_manager"], iid, success)?;
    if success {
        let qualified = bound_json(&serde_json::from_value(proof["native_qualification"].clone())?)?;
        c::native_valid(&qualified)?;
        ensure!(qualified["running_origin"] == private157::binding(&origin_binding) && qualified["invocation_id"] == iid
            && qualified["main_pid"] == pid && qualified["terminal_unix_microseconds"] == clock,
            "227 qualification differs from terminal owner");
    } else { ensure!(proof["native_qualification"].is_null(), "227 failed event cannot carry qualification"); }
    Ok((iid.into(), success, clock))
}
pub(super) fn terminal_status_identity(proof: &Value) -> Result<(String,String)> {
    let (iid,_,_) = terminal_proof(proof)?; Ok((admission::NATIVE_UNIT.into(),iid))
}
pub(super) fn terminal_predecessor(previous: &Value,p: &Plan,proof: &Value,sampled: &str,now:u64) -> Result<()> {
    let (iid,_,terminal_clock) = terminal_proof(proof)?;
    ensure!(p.first_epoch == 201 && p.last_epoch == 300 && p.admission_transition_guard.is_none()
        && previous["schema"] == SCHEMA && previous["sampled_at_utc"] == sampled && proof["sampled_at_utc"] == sampled
        && previous["observer_receipt"].as_str() == p.observer.path.to_str() && previous["observer_sha256"] == p.observer.sha256
        && proof["observer"] == private157::binding(&p.observer)
        && p.previous_fleet.as_ref().is_some_and(|b| proof["fleet"] == private157::binding(b)), "227 terminal replaced resource observation");
    let clock=proof["recorded_unix_seconds"].as_u64().context("227 terminal event clock")?;
    ensure!(clock >= terminal_clock/1_000_000 && clock <= now && now-clock <= 300
        && previous["recorded_unix_seconds"].as_u64().is_some_and(|n| n<clock), "227 terminal event stale/backdated");
    let old: Plan=serde_json::from_value(bound_json(&BoundFile{path:previous["plan"].as_str().context("227 terminal prior plan")?.into(),sha256:previous["plan_sha256"].as_str().context("227 terminal prior SHA")?.into()})?)?;
    ensure!(p.pipeline_claims==old.pipeline_claims && p.tracked_units==old.tracked_units
        && p.diagnostics.len()==old.diagnostics.len() && old.diagnostics.iter().all(|d| p.diagnostics.iter().any(|n| n.epoch==d.epoch && n.unit==d.unit && n.invocation_id==d.invocation_id && n.scratch_path==d.scratch_path && n.launch_receipt==d.launch_receipt))
        && p.gates.len()==old.gates.len() && p.schema==old.schema && p.observer==old.observer
        && p.status_receipt_directory==old.status_receipt_directory && p.runtime_handoff157==old.runtime_handoff157
        && p.continuation203_runtime_extension==old.continuation203_runtime_extension && p.epoch203_ram_auxiliary.is_none() && old.epoch203_ram_auxiliary.is_none(), "227 terminal changed unrelated owner/configuration history");
    let claims=p.pipeline_claims.iter().filter(|c| c.unit==admission::NATIVE_UNIT && c.invocation_id==iid).collect::<Vec<_>>();
    ensure!(claims.len()==1 && claims[0].evidence.first().is_some_and(|b| private157::binding(b)==proof["running_origin"]), "227 terminal missing registered original owner");
    c::native_claim(claims[0])?;
    for (epoch,gate) in &old.gates {
        let new=p.gates.get(epoch).context("227 terminal gate absent")?;
        ensure!(new.state==gate.state && gate.evidence.iter().all(|e|new.evidence.contains(e))
            && (*epoch==227 || (new.next_action==gate.next_action && new.evidence==gate.evidence)), "227 terminal changed completion/unrelated gate");
        if *epoch==227 { ensure!(new.evidence.iter().all(|e|gate.evidence.contains(e) || p.metadata_event.as_ref()==Some(e)
            || proof.get("native_qualification").is_some_and(|q|private157::binding(e)==*q)), "227 terminal unrelated evidence"); }
    }
    Ok(())
}
pub(super) fn terminal_census(p:&Plan,current:&BTreeMap<String,Value>) -> Result<()> {
    let Some(binding)=&p.metadata_event else{return Ok(())}; let proof=bound_json(binding)?;
    if proof["schema"]!=TERMINAL_SCHEMA{return Ok(())}
    let(iid,success,_)=terminal_proof(&proof)?;
    terminal_shape(current.get(admission::NATIVE_UNIT).context("227 terminal owner absent")?,&iid,success)?;
    let prior=bound_json(p.previous_fleet.as_ref().context("227 terminal predecessor missing")?)?;
    let mut protected=prior.clone();
    protected["active"]=Value::Array(prior["active"].as_array().context("227 terminal active census")?.iter().filter(|r|r["epoch"]!=227).cloned().collect());
    let mut view=current.clone();view.remove(admission::NATIVE_UNIT);admission::owners(&protected,&view)
}
#[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Spec {
    schema:String,running_origin:BoundFile,observer:BoundFile,fleet:BoundFile,native_qualification:Option<BoundFile>,output:PathBuf,
}
pub(super) fn capture() -> Result<()> {
    let args:Vec<_>=env::args().collect();ensure!(args.len()==7 && args[3]=="--spec-sha256" && args[5]=="--self-sha256" && unsafe{libc::geteuid()}==0,"capture-native227-terminal SPEC --spec-sha256 SHA --self-sha256 SHA (root)");
    ensure!(hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?))==args[6],"227 terminal helper digest differs");
    let spec_binding=BoundFile{path:args[2].clone().into(),sha256:args[4].clone()};let spec:Spec=serde_json::from_value(bound_json(&spec_binding)?)?;
    ensure!(spec.schema=="jetstreamer-private-epoch227-native-terminal-capture-spec-v1"
        && spec.output.parent().and_then(Path::parent)==Some(Path::new("/var/lib/jetstreamer"))
        && spec.output.parent().and_then(Path::file_name).and_then(|n|n.to_str()).is_some_and(|n|n.starts_with("horizon-227-terminal-"))
        && spec.output.file_name().is_some_and(|n|n=="event.json"),"227 terminal capture destination/scope");
    validate_output_destination(&spec.output)?;
    let origin=bound_json(&spec.running_origin)?;let iid=origin["invocation_id"].as_str().context("227 terminal IID")?;
    let pid=origin["main_pid"].as_u64().context("227 terminal PID")?;
    let prior=bound_json(&spec.fleet)?;let sample=bound_json(&spec.observer)?;
    ensure!(prior["sampled_at_utc"]==sample["recorded_at_utc"] && prior["observer_sha256"]==spec.observer.sha256,"227 terminal sample/fleet mismatch");
    let names=prior["unit_census"].as_object().context("227 prior census")?.keys().cloned().collect::<BTreeSet<_>>();
    let before=census(&names,201,300)?;
    let output=ProcessCommand::new("/usr/bin/journalctl").args(["--unit",admission::NATIVE_UNIT,"--output=json","--no-pager","--lines=4096"]).output()?;
    ensure!(output.status.success() && output.stdout.len()<=16<<20,"227 terminal journal unavailable/oversized");
    let rows=output.stdout.split(|b|*b==b'\n').filter(|b|!b.is_empty()).map(serde_json::from_slice::<Value>).collect::<std::result::Result<Vec<_>,_>>()?.into_iter().filter(|v|v["_SYSTEMD_INVOCATION_ID"]==iid || (v["_PID"]=="1" && v["INVOCATION_ID"]==iid)).collect::<Vec<_>>();
    let(success,clock)=journal_terminal(&rows,iid,pid)?;
    let path=spec.output.parent().unwrap().join("journal.json");private157::immutable_receipt(&path,&json!(rows))?;
    let journal:BoundFile=serde_json::from_value(private157::file_binding(&path)?)?;
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let event=json!({"schema":TERMINAL_SCHEMA,"epoch":227,"unit":admission::NATIVE_UNIT,"invocation_id":iid,"main_pid":pid,
        "running_origin":private157::binding(&spec.running_origin),"journal":private157::binding(&journal),"native_qualification":spec.native_qualification.as_ref().map(private157::binding),
        "observer":private157::binding(&spec.observer),"fleet":private157::binding(&spec.fleet),"sampled_at_utc":prior["sampled_at_utc"],"recorded_unix_seconds":now,
        "terminal_unix_microseconds":clock,"child_success":success,"terminal_manager":before[admission::NATIVE_UNIT],"capture_spec":private157::binding(&spec_binding),"capture_helper_sha256":args[6],
        "resource_samples_taken":0,"entry_replay":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    terminal_proof(&event)?;ensure!(before==census(&names,201,300)?,"227 terminal census changed");private157::immutable_receipt(&spec.output,&event)
}
#[cfg(test)] mod tests {
    use super::*;
    fn rows()->Vec<Value>{vec![json!({"_PID":"42","_SYSTEMD_UNIT":admission::NATIVE_UNIT,"_SYSTEMD_INVOCATION_ID":"a".repeat(32),"MESSAGE":"real child"}),json!({"_PID":"1","UNIT":admission::NATIVE_UNIT,"INVOCATION_ID":"a".repeat(32),"__REALTIME_TIMESTAMP":"123000000","MESSAGE":format!("{}: Deactivated successfully.",admission::NATIVE_UNIT)})]}
    #[test] fn terminal_journal_needs_exact_iid_pid_and_unique_pid1_outcome(){let r=rows();assert_eq!(journal_terminal(&r,&"a".repeat(32),42).unwrap(),(true,123000000));assert!(journal_terminal(&r,&"b".repeat(32),42).is_err());assert!(journal_terminal(&r,&"a".repeat(32),43).is_err());assert!(journal_terminal(&r[..1],&"a".repeat(32),42).is_err());let mut dup=r.clone();dup.push(r[1].clone());assert!(journal_terminal(&dup,&"a".repeat(32),42).is_err());}
    #[test] fn terminal_shape_accepts_pid1_cleared_identity_but_rejects_replacement_and_live(){let u=json!({"Id":admission::NATIVE_UNIT,"MainPID":"0","NRestarts":"0","InvocationID":"","ActiveState":"inactive","SubState":"dead","Result":"success"});terminal_shape(&u,&"a".repeat(32),true).unwrap();for(k,v)in[("MainPID",json!("42")),("InvocationID",json!("b".repeat(32))),("NRestarts",json!("1")),("Result",json!("timeout"))]{let mut bad=u.clone();bad[k]=v;assert!(terminal_shape(&bad,&"a".repeat(32),true).is_err());}}
}
