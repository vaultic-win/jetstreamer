// Capture the actual separate no-worker capability; declarations do not qualify it.
use super::*;
mod terminal {
    include!("epoch223_demotion_full_root_capability_terminal.rs");
}
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
fn historical_launch(actor: &Actor, plan: &Value, result: &Value, issuer: &Value) -> Result<()> {
    let path = plan["path"].as_str().context("223 capability historical plan path")?;
    let plan_sha = plan["sha256"].as_str().context("223 capability historical plan digest")?;
    ensure!(digest(plan_sha) && digest(&actor.executable.sha256)
            && actor.unit.starts_with("horizon-qualify-223-full-root-demotion-")
            && actor.unit.ends_with(".service")
            && actor.pid > 1 && actor.start_ticks > 0
            && actor.cgroup == format!("/system.slice/{}", actor.unit)
            && identity(&actor.invocation_id) && actor.invocation_id != "0".repeat(32)
            && identity(&actor.boot_id.replace('-', ""))
            && actor.executable.sha256 == issuer["executable"]["sha256"]
            && result["bindings"]["plan_path"] == path
            && result["bindings"]["plan_sha256"] == plan_sha
            && actor.expected_exec_start == format!(
                "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} --storage-capability ; ignore_errors=no }}",
                actor.executable.path.display(), actor.executable.path.display(), path,
                plan_sha, actor.executable.sha256),
        "full-root historical capability launch/plan/ELF/command differs");
    Ok(())
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
            && plan.canonical_diagnosis.is_none()
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
    historical_launch(&actor, &p["plan"], r, &p["issuer"])?;
    let original = terminal::lifecycle(&terminal::rows(journal)?, &actor)?;
    terminal::validate_evidence(&p["terminal_evidence"], &actor, &original)?;
    ensure!(p["terminal_manager"] == p["terminal_evidence"]["manager"]
            && p["terminal_adapter"] == "natural-success-cleared-or-collected-capability-v1",
        "full-root capability terminal evidence differs");
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
    let journal = bound_bytes(&spec.journal, 0, 16 << 20)?;
    let original = terminal::lifecycle(&terminal::rows(&journal)?, &actor)?;
    let terminal = terminal::snapshot(&actor, &original)?;
    let p = json!({"schema":"jetstreamer-epoch223-full-root-capability-proof-v1","capture_spec":binding,"issuer":issuer,
        "start":spec.start,"result":spec.result,"plan":spec.plan,"journal":spec.journal,"qualification":spec.qualification,
        "terminal_manager":terminal.manager,"terminal_evidence":terminal,
        "terminal_adapter":"natural-success-cleared-or-collected-capability-v1","captured_unix_millis":millis()?,"publication_authorized":false,"r2_mutations":false});
    check(
        &p,
        &start,
        &result,
        &journal,
        &plan,
        &read_bound(&spec.qualification)?,
    )?;
    ensure!(
        terminal.stable_with(&terminal::snapshot(&actor, &original)?),
        "full-root capability actor or complete PID1 history changed during capture"
    );
    observe(&issuer)?;
    issuance::published(&spec.output, &p)?;
    Ok(())
}

#[cfg(test)]
mod terminal_binding_tests {
    use super::*;
    fn fixture() -> (Actor, Value, Value, Value) {
        let plan = json!({"path":"/sealed/capability-plan.json","sha256":"a".repeat(64)});
        let issuer = json!({"executable":{"sha256":"b".repeat(64)}});
        let actor = Actor {
            unit:"horizon-qualify-223-full-root-demotion-capability-fixture.service".into(),
            invocation_id:"c".repeat(32),pid:101,start_ticks:123,
            cgroup:"/system.slice/horizon-qualify-223-full-root-demotion-capability-fixture.service".into(),
            boot_id:"d".repeat(32),
            executable:BoundFile {path:"/sealed/full-root-utility".into(),sha256:"b".repeat(64)},
            expected_exec_start:format!("{{ path=/sealed/full-root-utility ; argv[]=/sealed/full-root-utility /sealed/capability-plan.json --plan-sha256 {} --self-sha256 {} --storage-capability ; ignore_errors=no }}", "a".repeat(64),"b".repeat(64)),
        };
        let result = json!({"bindings":{"plan_path":plan["path"],"plan_sha256":plan["sha256"]}});
        (actor,plan,result,issuer)
    }
    #[test]
    fn original_capability_command_plan_and_actual_utility_are_bound_without_current_iid() {
        let (actor,plan,result,issuer)=fixture();
        historical_launch(&actor,&plan,&result,&issuer).unwrap();
        for field in ["path","sha256"] {
            let mut changed=plan.clone();changed[field]=json!("changed");
            assert!(historical_launch(&actor,&changed,&result,&issuer).is_err());
        }
        let mut changed=actor;changed.expected_exec_start=changed.expected_exec_start.replace(" --storage-capability", "");
        assert!(historical_launch(&changed,&plan,&result,&issuer).is_err());
    }
    #[test]
    fn historical_capability_rejects_other_elf_boot_unit_and_result_plan() {
        for kind in 0..6 {
            let (mut actor,plan,mut result,mut issuer)=fixture();
            match kind {
                0=>actor.unit="horizon-native-input-223-full-root-demotion-fixture.service".into(),
                1=>actor.invocation_id="0".repeat(32),
                2=>actor.boot_id="not-a-boot".into(),
                3=>actor.cgroup="/system.slice/foreign.service".into(),
                4=>issuer["executable"]["sha256"]=json!("e".repeat(64)),
                _=>result["bindings"]["plan_sha256"]=json!("f".repeat(64)),
            }
            assert!(historical_launch(&actor,&plan,&result,&issuer).is_err());
        }
    }
}
