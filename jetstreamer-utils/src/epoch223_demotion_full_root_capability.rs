// Capture the actual separate no-worker capability; declarations do not qualify it.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    issuer_unit: String,
    start: BoundFile,
    result: BoundFile,
    journal: BoundFile,
    plan: BoundFile,
    qualification: BoundFile,
    output: PathBuf,
}
fn raw(binding: &BoundFile) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_bytes(
        binding,
        1000,
        16 << 20,
    )?)?)
}
fn check(
    p: &Value,
    s: &Value,
    r: &Value,
    journal: &[u8],
    plan: &RuntimePlan,
    q: &Value,
) -> Result<()> {
    let actor: Actor = serde_json::from_value(s["actor"].clone())?;
    ensure!(
        p["schema"] == "jetstreamer-epoch223-full-root-capability-proof-v1"
            && plan.mode == "capability"
            && plan.prerequisites.is_none()
            && plan.bracket_proof.is_none()
            && plan.worker_qualification.is_none()
            && plan.capability.is_none()
            && plan.plan.node.sha256 == PARENT_SHA
            && plan.plan.target_slot == TERMINAL
            && plan.plan.terminal_slot == TERMINAL
            && s["schema"] == "jetstreamer-epoch223-full-root-demotion-capability-start-v1"
            && s["runtime_plan"] == p["plan"]
            && actor.unit == plan.plan.unit
            && r["schema"] == "jetstreamer-epoch223-full-root-demotion-capability-v1"
            && r["invocation_id"] == actor.invocation_id
            && r["bindings"]["self_sha256"] == actor.executable.sha256
            && r["parent_preflight"]["schema"]
                == "jetstreamer-private-epoch223-full-root-demotion-preflight-v1"
            && r["parent_preflight"]["worker_sha256"] == WORKER
            && r["parent_preflight"]["terminal_slot"] == TERMINAL
            && r["parent_preflight"]["worker_spawned"] == false
            && r["parent_preflight"]["complete_epoch_span_covered"] == false
            && r["parent_preflight"]["publication_authorized"] == false
            && r["r2_mutations"] == false
            && p["publication_authorized"] == false
            && p["r2_mutations"] == false
            && r["parent_preflight"]["canonical_terminal_accounts_hash"]
                == "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7"
            && r["parent_preflight"]["canonical_terminal_bank_hash"]
                == "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"
            && r["worker_spawned"] == false
            && r["replay_launch_authorized"] == false
            && r["publication_authorized"] == false
            && q["schema"] == "jetstreamer-epoch223-full-root-demotion-role-qualification-v1"
            && q["executable_sha256"] == p["issuer"]["executable"]["sha256"]
            && q["capability_capture_qualified"] == true,
        "full-root actual capability/task/qualification differs"
    );
    native_capture::journal_valid(journal, &actor)?;
    let m = &p["terminal_manager"];
    ensure!(
        m["Id"] == actor.unit
            && m["InvocationID"] == actor.invocation_id
            && m["NRestarts"] == "0"
            && m["MainPID"] == "0"
            && m["ActiveState"] == "inactive"
            && m["SubState"] == "dead"
            && m["Result"] == "success"
            && m["ExecMainStatus"] == "0"
            && m["ExecStart"]
                .as_str()
                .is_some_and(|c| command_matches(c, &actor.expected_exec_start)),
        "full-root capability lacks its genuine successful terminal actor"
    );
    Ok(())
}
pub(super) fn validate(binding: &BoundFile) -> Result<()> {
    let p: Value = read_bound(binding)?;
    let get = |key: &str| -> Result<BoundFile> { Ok(serde_json::from_value(p[key].clone())?) };
    let plan: RuntimePlan = read_bound(&get("plan")?)?;
    let spec: Spec = read_bound(&get("capture_spec")?)?;
    ensure!(
        p["start"] == binding_value(&spec.start)
            && p["result"] == binding_value(&spec.result)
            && p["plan"] == binding_value(&spec.plan)
            && p["journal"] == binding_value(&spec.journal)
            && p["qualification"] == binding_value(&spec.qualification),
        "full-root capability capture spec differs"
    );
    check(
        &p,
        &raw(&get("start")?)?,
        &raw(&get("result")?)?,
        &bound_bytes(&get("journal")?, 0, 16 << 20)?,
        &plan,
        &read_bound(&get("qualification")?)?,
    )
}
pub(super) fn capture(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let spec: Spec = read_bound(binding)?;
    ensure!(
        spec.schema == "jetstreamer-epoch223-full-root-capability-capture-spec-v1",
        "full-root capability capture schema"
    );
    let issuer = roles::own_role(
        &spec.issuer_unit,
        "capture-epoch223-full-root-demotion-capability",
        binding,
        executable,
    )?;
    let start = raw(&spec.start)?;
    let result = raw(&spec.result)?;
    let actor: Actor = serde_json::from_value(start["actor"].clone())?;
    let plan: RuntimePlan = read_bound(&spec.plan)?;
    let keys =
        "Id,InvocationID,NRestarts,MainPID,ActiveState,SubState,Result,ExecMainStatus,ExecStart";
    let manager = properties_with(&actor.unit, keys)?;
    let p = json!({"schema":"jetstreamer-epoch223-full-root-capability-proof-v1","capture_spec":binding,"issuer":issuer,
        "start":spec.start,"result":spec.result,"plan":spec.plan,"journal":spec.journal,"qualification":spec.qualification,
        "terminal_manager":manager,"captured_unix_millis":millis()?,"publication_authorized":false,"r2_mutations":false});
    check(
        &p,
        &start,
        &result,
        &bound_bytes(&spec.journal, 0, 16 << 20)?,
        &plan,
        &read_bound(&spec.qualification)?,
    )?;
    ensure!(
        properties_with(&actor.unit, keys)? == manager,
        "full-root capability actor changed during capture"
    );
    observe(&issuer)?;
    issuance::published(&spec.output, &p)?;
    Ok(())
}
