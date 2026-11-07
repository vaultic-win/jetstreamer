//! Actual captured Frame plus genuinely authenticated current terminal145 guard.
use super::*;

#[derive(Deserialize)]
struct ControlSources {
    observer: BoundFile, fleet: BoundFile, fleet_plan: BoundFile,
    completion: BoundFile, resource_parent: BoundFile,
    phase_events: Vec<EventBinding>, reader191: BoundFile,
    transfer191: BoundFile, correction191: BoundFile, closed185: BoundFile,
    standing: BoundFile, guards: Vec<GuardSpec>,
}

#[test]
#[ignore = "Root must bind genuine current Frame Sources and permit readonly native terminal145 authentication"]
fn actual_terminal145_periodic_guard_composes_before_current_coordinator_without_hiding_other_rows() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root native qualification required");
    let manifest: BoundFile = serde_json::from_str(&std::env::var("JETSTREAMER_CURRENT_TERMINAL145_FIXTURE_BINDING")?)?;
    let manifest = protected_generated(&manifest)?;
    let fixture = protected_generated(&serde_json::from_value(manifest["reader_spec"].clone())?)?;
    let src: ControlSources = serde_json::from_value(fixture["resource_accounting"].clone())?;
    let mut values = std::collections::BTreeMap::new();
    for (key,bound) in [("observer",&src.observer),("fleet",&src.fleet),("fleet_plan",&src.fleet_plan),
        ("completion",&src.completion),("parent",&src.resource_parent),("reader",&src.reader191),
        ("transfer",&src.transfer191),("correction",&src.correction191),("closed185",&src.closed185),("standing",&src.standing)] {
        values.insert(key, protected_generated(bound)?);
    }
    let events = src.phase_events.iter().map(|e|phase_event_source(&e.source)).collect::<Result<Vec<_>>>()?;
    let selected = src.phase_events.iter().position(|e|json!(e.source)==manifest["frame"]).context("genuine current Frame event absent")?;
    let original_clock = events[selected]["recorded_unix_seconds"].as_u64().context("genuine original Frame clock")?;
    let spec = SpecView { observer:&src.observer,fleet:&src.fleet,fleet_plan:&src.fleet_plan,
        completion:&src.completion,resource_parent:&src.resource_parent,phase_events:&src.phase_events,
        reader191:&src.reader191,transfer191:&src.transfer191,correction191:&src.correction191,
        closed185:&src.closed185,guards:&src.guards,allow_retained144_terminal:true };
    let bundle = BundleView { observer:&values["observer"],fleet:&values["fleet"],fleet_plan:&values["fleet_plan"],
        completion:&values["completion"],parent:&values["parent"],events:&events,reader:&values["reader"],
        transfer:&values["transfer"],correction:&values["correction"],closed185:&values["closed185"],standing:&values["standing"] };
    crate::fleet::epoch186::evidence::accepted_basis(&spec,&bundle,original_clock)?;
    let mut selector: Selector = serde_json::from_value(fixture["resource_accounting"]["live145_prefix_export"].clone())?;
    selector.terminal_retained = true;
    let captured = actual(Some(&selector),custody::now()?)?.context("genuine current terminal145 capture")?;
    ensure!(terminal::retained(&captured),"actual failed74 retained endpoint required");
    let expected = bundle.fleet["unit_census"].as_object().context("original genuine fleet native census")?;
    let mut current = expected.iter().map(|(k,v)|(k.clone(),v.clone())).collect::<std::collections::BTreeMap<_,_>>();
    ensure!(current.contains_key(GUARD) && current.contains_key(TIMER),"actual prefix family absent from original census");
    let guard = FLEET_SERVICE_FIELDS.into_iter().map(|k|(k.to_owned(),captured["guard_native"][k].clone())).collect::<serde_json::Map<_,_>>();
    let timer = FLEET_TIMER_FIELDS.into_iter().map(|k|(k.to_owned(),captured["timer_native"][k].clone())).collect::<serde_json::Map<_,_>>();
    current.insert(GUARD.into(),json!(guard));
    current.insert(TIMER.into(),json!(timer));
    let raw_saved = serde_json::to_value(&current)?;
    ensure!(serde_json::to_value(&current)? != bundle.fleet["unit_census"],"this native control needs a genuine original periodic metadata change");
    ensure!(io::completed_coordinator_basis(&spec,&bundle,&current).is_err(),"original failure must be reproduced without the selected authenticated145 composition");
    coordinator_basis(&spec,&bundle,&current,Some(&captured))?;
    ensure!(coordinator_basis(&spec,&bundle,&current,None).is_err(),"omitted selected capture cannot hide live145 changes");
    let mut crossed = captured.clone(); crossed["peer"]["invocation_id"]=json!("f".repeat(32));
    ensure!(coordinator_basis(&spec,&bundle,&current,Some(&crossed)).is_err(),"crossed actor peer must reject");
    let mut bad_guard = current.clone();bad_guard.get_mut(GUARD).context("actual guard row")?["MemoryMax"]=json!("1");
    ensure!(coordinator_basis(&spec,&bundle,&bad_guard,Some(&captured)).is_err(),"changed hard guard bounds must reject");
    let foreign = current.keys().find(|n| ![ACTOR,GUARD,TIMER].contains(&n.as_str()) && !crate::fleet::ordinary199::FAMILY.contains(&n.as_str())).context("genuine unrelated owner required")?.clone();
    let mut changed = current.clone();changed.get_mut(&foreign).context("unrelated original row")?["NRestarts"]=json!("1");
    ensure!(coordinator_basis(&spec,&bundle,&changed,Some(&captured)).is_err(),"another owner change cannot borrow145 comparison");
    ensure!(serde_json::to_value(&current)?==raw_saved,"raw native evidence was rewritten");
    println!("{}",json!({"schema":"actual-terminal145-current-coordinator-composition-control-v1",
        "original_Frame":manifest["frame"],"actual_terminal145_capture":captured,
        "actual_guard_native":current[GUARD],"actual_timer_native":current[TIMER],
        "original_failure_reproduced":true,"selected_authenticated_comparison_passed":true,
        "raw_native_preserved":true,"no_other_owner_exemption":true,"resource_credit_bytes":0,"replay_launch_authorized":false}));
    Ok(())
}
