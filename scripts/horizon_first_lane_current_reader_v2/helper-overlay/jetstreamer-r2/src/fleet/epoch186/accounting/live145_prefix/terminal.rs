//! One deliberately narrow failed74 endpoint. Terminality is retained debt,
//! never fresh guard coverage, restart permission, or a resource release.
use super::*;
const PHASE: &str = "terminal-retained-failed74";
const FAILED_AT: u64 = 1_794_072_782;
const SCHEMA: &str = "live145-v8g1-terminal-retained-accounting-capture-v1";
pub(super) fn retained(v: &Value) -> bool { v["lifecycle"] == PHASE }
pub(super) fn selected_phase(selected: bool, failed: bool) -> Result<()> {
    ensure!(selected == failed, "live145 lifecycle requires explicit terminal-retained selection for the exact failed actor");
    Ok(())
}
pub(super) fn is_terminal(v: &Value) -> bool {
    v["ActiveState"] == "failed" && v["SubState"] == "failed"
}
pub(super) fn same_phase(a: &Value, b: &Value) -> Result<()> {
    ensure!(retained(a) == retained(b), "live145 changed lifecycle during finite accounting");
    if retained(a) {
        for v in [a,b] {
            ensure!(v["schema"] == SCHEMA && v["token_is_historical_only"] == true
                && v["live_guard_coverage_claimed"] == false
                && v["memory_or_DATA_credit_bytes"] == 0 && v["replay_launch_authorized"] == false,
                "terminal145 lifecycle envelope claims coverage or credit");
            native::drained_shape(&v["drained"])?;
        }
        ensure!(a["lifecycle"] == b["lifecycle"]
            && a["terminal_evidence"] == b["terminal_evidence"]
            && a["token"] == b["token"] && a["token_sha256"] == b["token_sha256"]
            && a["actor_full"] == b["actor_full"],
            "terminal145 original failure, last token or native actor changed");
    }
    Ok(())
}
fn common(v: &Value, role: &str, memory: u64, cpu: &str, mode: &str) -> Result<()> {
    let memory_native = memory.to_string();
    ensure!(v["Id"] == role && v["LoadState"] == "loaded"
        && v["NRestarts"] == "0" && v["Restart"] == "no" && v["Type"] == "exec"
        && v["User"] == "root" && v["MemoryMax"].as_str() == Some(memory_native.as_str())
        && v["MemorySwapMax"] == "0" && v["TasksMax"] == "512"
        && v["CPUQuotaPerSecUSec"] == cpu
        && v["ExecStart"].as_str().is_some_and(|s| s.starts_with(&command(mode)) && s.matches("argv[]=").count() == 1),
        "terminal145 original command, identity or hard bounds changed");
    Ok(())
}
fn failed_actor(v: &Value, full: &Value, a: &model::Admission) -> Result<()> {
    let actor_pid_native = a.actor_pid.to_string();
    common(v, ACTOR, 80u64 << 30, "8s", "extract")?;
    ensure!(v["InvocationID"] == IID && is_terminal(v) && v["MainPID"] == "0"
        && v["ControlGroup"] == "" && v["Result"] == "exit-code"
        && v["ExecMainCode"] == "1" && v["ExecMainStatus"] == "74"
        && full["ExecMainPID"].as_str() == Some(actor_pid_native.as_str())
        && full["ExecMainExitTimestamp"] == "Sat 2026-11-07 17:33:02 UTC"
        && full["ControlPID"] == "0" && full["Job"] == ""
        && full["DropInPaths"] == "" && full["ExecStartPre"] == ""
        && full["User"] == "root" && full["Group"] == "root"
        && full["KillMode"] == "control-group",
        "terminal145 requires original PID1 failed74 actor with no replacement, job or pre-hook");
    for key in ["Id","LoadState","ActiveState","SubState","InvocationID","MainPID","NRestarts","Restart","Type","ControlGroup","Result","ExecMainCode","ExecMainStatus","ExecStart","MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec","User"] {
        ensure!(full[key] == v[key], "terminal145 full/narrow actor differs: {key}");
    }
    Ok(())
}
/// Failed periodic fires retain their real failure; only this terminal actor's
/// guard may use this predicate. Running fires still pass native::owner.
pub(super) fn guard(v: &Value) -> Result<()> {
    common(v, GUARD, 256u64 << 20, "1s", "guard")?;
    ensure!(v["InvocationID"].as_str().is_some_and(|s|custody::hex(s,32)), "terminal145 guard IID");
    let running = v["ActiveState"] == "active" && v["SubState"] == "running"
        && v["MainPID"].as_str().and_then(|s|s.parse::<u32>().ok()).is_some_and(|n|n>1)
        && v["ControlGroup"] == format!("/system.slice/{GUARD}");
    let success = v["ActiveState"] == "inactive" && v["SubState"] == "dead"
        && v["Result"] == "success" && v["ExecMainCode"] == "1" && v["ExecMainStatus"] == "0";
    let failed = is_terminal(v) && v["Result"] == "exit-code"
        && v["ExecMainCode"] == "1" && v["ExecMainStatus"] == "1";
    ensure!(running || ((success || failed) && v["MainPID"] == "0" && v["ControlGroup"] == ""),
        "terminal145 guard queued, restarting or unknown failure");
    Ok(())
}
fn full_guard(v: &Value, g: &Value) -> Result<()> {
    ensure!(g["DropInPaths"] == "" && g["ExecStartPre"] == "" && g["ControlPID"] == "0"
        && g["Job"] == "" && g["User"] == "root" && g["Group"] == "root"
        && g["KillMode"] == "control-group", "terminal145 guard custody changed");
    for k in ["Id","InvocationID","ActiveState","SubState","MainPID","ControlGroup","ExecStart","Result","ExecMainCode","ExecMainStatus"] {
        ensure!(v[k] == g[k], "terminal145 full/narrow guard differs: {k}");
    }
    Ok(())
}
fn no_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => anyhow::bail!("terminal145 unexpected completion or alternative failure evidence"),
    }
}
fn snapshot(path: &Path) -> Result<Value> {
    let bound = custody::binding(path)?;
    let bytes = custody::bytes(&bound, 8 << 20, false)?;
    let value = io::unique_json(&bytes)?;
    Ok(json!({"bound":bound,"source_bytes":bytes,"value":value}))
}
fn snapshot_shape(v: &Value, path: &Path) -> Result<Value> {
    let b: model::Bound = serde_json::from_value(v["bound"].clone())?;
    let bytes: Vec<u8> = serde_json::from_value(v["source_bytes"].clone())?;
    ensure!(b.path == path && bytes.len() <= 8 << 20 && custody::sha(&bytes) == b.sha256
        && io::unique_json(&bytes)? == v["value"], "terminal145 raw failure custody crossed");
    Ok(v["value"].clone())
}
fn evidence_shape(e: &Value, p: &model::Plan, a: &model::Admission, clock: u64) -> Result<u64> {
    let w = snapshot_shape(&e["watchdog"], &Path::new(STATE).join("watchdog-failure.json"))?;
    let at = w["at_unix_seconds"].as_u64().context("terminal145 failure clock")?;
    ensure!(w["schema"] == "horizon-epoch145-private-extractor-watchdog-failure-v1"
        && w["actor_iid"] == IID && at == FAILED_AT && at >= a.accepted_at && at <= clock
        && w["error"] == "missing/stale/crossed native guard proof"
        && w["phase"].as_u64().is_some()
        && w["charged_output_bytes"].as_u64().is_some_and(|n|n<=p.output_maximum_bytes)
        && w["authority"] == json!({"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"replay_launch_authorized":false})
        && e["extraction_complete_absent"] == true && e["extraction_failure_absent"] == true,
        "terminal145 is not original stale-token watchdog failure");
    Ok(at)
}
fn terminal_peer(s: &Selector, p: &model::Plan, actor: &Value) -> Value {
    let mut v = peer(s,p,actor);
    v["state"] = json!(PHASE);
    v["terminal_retained"] = json!(true);
    v["live_guard_coverage_claimed"] = json!(false);
    v["cpu_quota_micros_retained"] = json!(9_000_000u64);
    v
}
fn historical_token(v: &Value, p: &model::Plan, a: &model::Admission, pb: &model::Bound, ab: &model::Bound, at: u64, boot: u64) -> Result<()> {
    let t: model::Token = serde_json::from_value(v.clone())?;
    token(&t,p,a,pb,ab,t.at_unix_seconds,t.at_boottime_millis)?;
    ensure!(at.checked_sub(t.at_unix_seconds).is_some_and(|age|age >= 90)
        && t.at_unix_seconds <= p.execution_deadline && t.at_boottime_millis <= boot,
        "terminal145 token newer than original failure or capture");
    Ok(())
}
pub(super) fn actual(s: &Selector, p: &model::Plan, a: &model::Admission, pb: &model::Bound, ab: &model::Bound, actor: &Value, clock: u64) -> Result<Value> {
    let actor_full = native::show(ACTOR)?;
    failed_actor(actor,&actor_full,a)?;
    native::original()?;
    no_file(&Path::new(STATE).join("extraction-complete.json"))?;
    no_file(&Path::new(STATE).join("extraction-failure.json"))?;
    let evidence = json!({"watchdog":snapshot(&Path::new(STATE).join("watchdog-failure.json"))?,
        "extraction_complete_absent":true,"extraction_failure_absent":true});
    let captured_at = custody::now()?;
    ensure!(clock <= captured_at, "terminal145 future capture request");
    let at = evidence_shape(&evidence,p,a,captured_at)?;
    let boot = custody::boottime()?;
    let bytes = custody::token_snapshot(&Path::new(STATE).join("guard-latest.json"))?;
    let token_value = io::unique_json(&bytes)?;
    historical_token(&token_value,p,a,pb,ab,at,boot)?;
    let timer = native::timer(p)?; timer_native(&timer)?;
    let g = io::properties(GUARD)?; guard(&g)?;
    let g_full = native::show(GUARD)?; full_guard(&g,&g_full)?;
    let allowed_guard = if g["ActiveState"] == "active" {
        let pid: u32 = string(&g,"/MainPID")?.parse()?;
        native::owner(p,pb,true,pid,string(&g,"/InvocationID")?,native::ticks(pid)?)?;
        Some(pid)
    } else { native::empty_cgroup(GUARD)?; None };
    // No controller/qualification exemption; only the actual authenticated guard
    // may still hold this family's paths while its timer continues naturally.
    let drained = native::terminal_drained(p,pb,a,allowed_guard)?;
    ensure!(io::properties(ACTOR)? == *actor && native::show(ACTOR)? == actor_full,
        "terminal145 actor changed during finite capture");
    no_file(&Path::new(STATE).join("extraction-complete.json"))?;
    no_file(&Path::new(STATE).join("extraction-failure.json"))?;
    ensure!(snapshot(&Path::new(STATE).join("watchdog-failure.json"))? == evidence["watchdog"],
        "terminal145 failure changed during capture");
    let timer_after = native::timer(p)?; timer_native(&timer_after)?;
    for k in ["Id","LoadState","InvocationID","ActiveState","Triggers","DropInPaths","Job"] {
        ensure!(timer[k] == timer_after[k], "terminal145 timer changed during capture");
    }
    // A new token after failure is never silently promoted to retained history.
    ensure!(custody::token_snapshot(&Path::new(STATE).join("guard-latest.json"))? == bytes,
        "terminal145 last original token changed during capture");
    let row = terminal_peer(s,p,actor); peer_shape(&row)?;
    let captured = json!({"schema":SCHEMA,"lifecycle":PHASE,"captured_at":captured_at,
        "captured_boottime_millis":boot,"plan":binding(&s.plan),"peer":row,
        "token":token_value,"token_sha256":custody::sha(&bytes),"token_source_bytes":bytes,
        "token_is_historical_only":true,"live_guard_coverage_claimed":false,
        "terminal_evidence":evidence,"drained":drained,"actor_full":actor_full,
        "actor_native":actor,"guard_native":g,"guard_full":g_full,"timer_native":timer,
        "archive_body_reads":false,"memory_or_DATA_credit_bytes":0,"replay_launch_authorized":false});
    verify(&captured)?;
    Ok(captured)
}
/// Recorded endpoints are verified with original bound plan/readiness/admission;
/// a terminal token remains historical and is never evaluated as current health.
pub(super) fn verify(v: &Value) -> Result<()> {
    ensure!(retained(v) && v["schema"] == SCHEMA && v["token_is_historical_only"] == true
        && v["live_guard_coverage_claimed"] == false && v["archive_body_reads"] == false
        && v["memory_or_DATA_credit_bytes"] == 0 && v["replay_launch_authorized"] == false,
        "terminal145 envelope claims live coverage or authority");
    let bindings = v["peer"]["source_bindings"].as_array().context("terminal145 source bindings")?;
    ensure!(bindings.len() >= 4, "terminal145 original source bindings absent");
    let s: Selector = serde_json::from_value(json!({"plan":bindings[0],"ready":bindings[1],
        "admission":bindings[2],"guard_before_source":bindings[3],"terminal_retained":true}))?;
    exact(&s)?;
    let p: model::Plan = serde_json::from_value(value(&s.plan,true)?)?;
    let a: model::Admission = serde_json::from_value(value(&s.admission,false)?)?;
    let pb = old(&s.plan);
    let ab = model::Bound { path:p.state_root.join("admission.json"),sha256:s.admission.sha256.clone() };
    plan_shape(&p,&a,&value(&s.ready,false)?,&value(&s.guard_before_source,false)?,&pb,&ab,a.accepted_at)?;
    sealed_program(&p)?;
    ensure!(v["plan"] == json!(pb), "terminal145 capture plan crossed");
    let clock = v["captured_at"].as_u64().context("terminal145 capture clock")?;
    let boot = v["captured_boottime_millis"].as_u64().context("terminal145 capture boot clock")?;
    let at = evidence_shape(&v["terminal_evidence"],&p,&a,clock)?;
    let bytes: Vec<u8> = serde_json::from_value(v["token_source_bytes"].clone())?;
    ensure!(bytes.len() <= 1 << 20 && custody::sha(&bytes) == v["token_sha256"]
        && io::unique_json(&bytes)? == v["token"], "terminal145 raw last token changed");
    historical_token(&v["token"],&p,&a,&pb,&ab,at,boot)?;
    failed_actor(&v["actor_native"],&v["actor_full"],&a)?;
    guard(&v["guard_native"])?; full_guard(&v["guard_native"],&v["guard_full"])?;
    timer_native(&v["timer_native"])?;
    native::drained_shape(&v["drained"])?;
    peer_shape(&v["peer"])?;
    ensure!(v["peer"] == terminal_peer(&s,&p,&v["actor_native"]), "terminal145 retained promises crossed");
    Ok(())
}

#[cfg(test)]
#[path = "terminal_tests.rs"]
mod tests;
