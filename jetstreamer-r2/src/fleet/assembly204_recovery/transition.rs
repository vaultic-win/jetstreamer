//! Rebuild the exact derivative plan from its accepted raw predecessor. Only
//! epoch-204 recovery fields and authenticated old-claim history can change.
use super::*;
pub(in crate::fleet) const EVENT_SCHEMA: &str =
    "jetstreamer-epoch204-assembly-recovery-fleet-transition-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    schema: String,
    original_plan: BoundFile,
    previous_fleet: BoundFile,
    observer: BoundFile,
    claim: Claim,
    output_directory: PathBuf,
}
fn derivative(x: &Prepare, old: &Value, previous: &Value) -> Result<Value> {
    ensure!(
        old["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && previous["schema"] == SCHEMA
            && old["first_epoch"] == 201
            && old["last_epoch"] == 300
            && previous["first_epoch"] == 201
            && previous["last_epoch"] == 300
            && previous["plan"] == x.original_plan.path.to_string_lossy().as_ref()
            && previous["plan_sha256"] == x.original_plan.sha256,
        "204 recovery transition lost accepted predecessor"
    );
    let frame = read(&x.claim.frame)?;
    let observer = bound_json(&x.observer)?;
    ensure!(
        frame["previous_fleet"] == private157::binding(&x.previous_fleet)
            && frame["observer"] == private157::binding(&x.observer),
        "204 recovery transition and frame predecessor differ"
    );
    let current = serde_json::from_value(frame["unit_census_after"].clone())?;
    row(
        &x.claim,
        &observer,
        &current,
        n(&frame, "sampled_unix_millis")? / 1000,
    )?;
    let recovery = read(&x.claim.recovery_plan)?;
    let failure = read(&serde_json::from_value(
        recovery["original_terminal"].clone(),
    )?)?;
    custody::validate_terminal_saved(&failure)?;
    active_projection(x, old, previous, &frame)
}
// No row/context recursion: historical event authentication reuses this exact
// projection after checking the immutable claim and predecessor bindings.
fn active_projection(x: &Prepare, old: &Value, previous: &Value, frame: &Value) -> Result<Value> {
    let mut next = old.clone();
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.extend(
        previous["unit_census"]
            .as_object()
            .context("204 previous census")?
            .keys()
            .cloned(),
    );
    tracked.extend(
        frame["unit_census_after"]
            .as_object()
            .context("204 frame census")?
            .keys()
            .cloned(),
    );
    let mut capped = old
        .get("capped204205_work")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut history = old
        .get("capped204205_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    capped.retain(|claim| {
        if claim["epoch"] == 204 {
            history.push(claim.clone());
            false
        } else {
            true
        }
    });
    next["capped204205_work"] = json!(capped);
    next["capped204205_history"] = json!(history);
    let mut recovery_history = old
        .get("assembly204_recovery_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(prior) = old.get("assembly204_recovery").filter(|v| !v.is_null()) {
        recovery_history.push(prior.clone());
    }
    next["assembly204_recovery_history"] = json!(recovery_history);
    next["assembly204_recovery"] = serde_json::to_value(&x.claim)?;
    next["assembly204_recovery_terminal"] = Value::Null;
    next["tracked_units"] = json!(tracked);
    next["observer"] = private157::binding(&x.observer);
    next["previous_fleet"] = private157::binding(&x.previous_fleet);
    next["admission_transition_guard"] = Value::Null;
    next["output"] = json!(x.output_directory.join("fleet.json"));
    Ok(next)
}
pub(super) fn prepare(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: Prepare = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-prepare-spec-v1",
        "204 recovery prepare spec"
    );
    private(&x.output_directory)?;
    let old = bound_json(&x.original_plan)?;
    let previous = bound_json(&x.previous_fleet)?;
    let mut next = derivative(&x, &old, &previous)?;
    let frame = read(&x.claim.frame)?;
    let event = write(
        &x.output_directory.join("event.json"),
        &json!({"schema":EVENT_SCHEMA,"original_plan":x.original_plan,
        "previous_fleet":x.previous_fleet,"observer":x.observer,"claim":x.claim,"sampled_at_utc":frame["sampled_at_utc"],
        "metadata_only":true,"resource_samples_taken":0,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    next["metadata_event"] = private157::binding(&event);
    write(&x.output_directory.join("plan.json"), &next)?;
    Ok(())
}
pub(in crate::fleet) fn event_predecessor(
    previous: &Value,
    plan: &Plan,
    binding: &BoundFile,
    event: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        event["schema"] == EVENT_SCHEMA
            && event["metadata_only"] == true
            && event["resource_samples_taken"] == 0
            && event["previous_fleet"]
                == plan
                    .previous_fleet
                    .as_ref()
                    .map(private157::binding)
                    .unwrap_or(Value::Null)
            && event["observer"] == private157::binding(&plan.observer)
            && plan.admission_transition_guard.is_none(),
        "204 recovery event lost exact context"
    );
    deny(&event["authority"])?;
    let at = utc_seconds(s(event, "sampled_at_utc")?)?;
    ensure!(
        utc_seconds(sample)? <= at && at <= now && now - at <= 900,
        "204 recovery event stale/future"
    );
    if event["action"] == "terminal" {
        let x = TerminalPrepare {
            schema: "jetstreamer-epoch204-assembly-recovery-terminal-prepare-spec-v1".into(),
            original_plan: serde_json::from_value(event["original_plan"].clone())?,
            previous_fleet: serde_json::from_value(event["previous_fleet"].clone())?,
            observer: serde_json::from_value(event["observer"].clone())?,
            observer_history: serde_json::from_value(
                event.get("observer_history").cloned().unwrap_or(json!([])),
            )?,
            full209_terminal_peer: serde_json::from_value(
                event
                    .get("full209_terminal_peer")
                    .cloned()
                    .unwrap_or(Value::Null),
            )?,
            terminal: serde_json::from_value(event["terminal"].clone())?,
            output_directory: binding
                .path
                .parent()
                .context("204 terminal derivative parent")?
                .into(),
        };
        let mut expected = terminal_derivative(&x, &bound_json(&x.original_plan)?, previous)?;
        let actual = read(binding)?;
        expected["metadata_event"] = actual["metadata_event"].clone();
        ensure!(
            expected == actual,
            "204 terminal transition changed unrelated plan fields"
        );
        return Ok(());
    }
    let x = Prepare {
        schema: "jetstreamer-epoch204-assembly-recovery-prepare-spec-v1".into(),
        original_plan: serde_json::from_value(event["original_plan"].clone())?,
        previous_fleet: serde_json::from_value(event["previous_fleet"].clone())?,
        observer: serde_json::from_value(event["observer"].clone())?,
        claim: serde_json::from_value(event["claim"].clone())?,
        output_directory: binding
            .path
            .parent()
            .context("204 derivative plan parent")?
            .into(),
    };
    let mut expected = derivative(&x, &bound_json(&x.original_plan)?, previous)?;
    let actual = read(binding)?;
    expected["metadata_event"] = actual["metadata_event"].clone();
    ensure!(
        expected == actual,
        "204 recovery handoff changed unrelated owner/gate/history fields"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalPrepare {
    schema: String,
    original_plan: BoundFile,
    previous_fleet: BoundFile,
    observer: BoundFile,
    #[serde(default)]
    observer_history: Vec<BoundFile>,
    #[serde(default)]
    full209_terminal_peer: Option<full209_terminal_peer::Proof>,
    terminal: BoundFile,
    output_directory: PathBuf,
}
fn terminal_derivative(x: &TerminalPrepare, old: &Value, previous: &Value) -> Result<Value> {
    ensure!(
        old["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && previous["schema"] == SCHEMA
            && previous["plan"] == x.original_plan.path.to_string_lossy().as_ref()
            && previous["plan_sha256"] == x.original_plan.sha256
            && old["first_epoch"] == 201
            && old["last_epoch"] == 300,
        "204 terminal transition predecessor scope"
    );
    let claim: Claim = serde_json::from_value(old["assembly204_recovery"].clone())?;
    let launch = read(&claim.actor_launch)?;
    let t = read(&x.terminal)?;
    terminal_context_join(x, &t)?;
    ensure!(
        t["unit"] == launch["unit"] && t["invocation_id"] == launch["invocation_id"],
        "204 terminal transition replaced its actor"
    );
    if t["result"] == "natural_success" {
        ownership::validate_success_terminal(
            &t,
            s(&launch, "unit")?,
            s(&launch, "invocation_id")?,
        )?;
    } else {
        ownership::validate_failure_terminal(&t)?;
    }
    terminal_projection(x, old, &claim)
}
fn terminal_projection(x: &TerminalPrepare, old: &Value, claim: &Claim) -> Result<Value> {
    let mut next = old.clone();
    let mut history = old
        .get("assembly204_recovery_history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(serde_json::to_value(claim)?);
    next["assembly204_recovery_history"] = json!(history);
    next["assembly204_recovery"] = Value::Null;
    next["assembly204_recovery_terminal"] = private157::binding(&x.terminal);
    next["observer"] = private157::binding(&x.observer);
    next["previous_fleet"] = private157::binding(&x.previous_fleet);
    next["admission_transition_guard"] = Value::Null;
    next["output"] = json!(x.output_directory.join("fleet.json"));
    Ok(next)
}
/// Reconstruct only the saved plan. Runtime row and terminal validation remain
/// at their existing creation gates; this reader authenticates their lineage
/// without recursively reopening work-context ancestors.
pub(super) fn saved_event_plan(
    event: &Value,
    old: &Value,
    previous: &Value,
    frame: Option<&Value>,
    directory: &Path,
) -> Result<Value> {
    let original_plan: BoundFile = serde_json::from_value(event["original_plan"].clone())?;
    ensure!(
        old["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && old["first_epoch"] == 201
            && old["last_epoch"] == 300
            && previous["plan"] == original_plan.path.to_string_lossy().as_ref()
            && previous["plan_sha256"] == original_plan.sha256,
        "204 saved event original plan differs"
    );
    let previous_fleet = serde_json::from_value(event["previous_fleet"].clone())?;
    let observer = serde_json::from_value(event["observer"].clone())?;
    let expected = if event["action"] == "terminal" {
        let x = TerminalPrepare {
            schema: String::new(),
            original_plan,
            previous_fleet,
            observer,
            observer_history: serde_json::from_value(
                event.get("observer_history").cloned().unwrap_or(json!([])),
            )?,
            full209_terminal_peer: serde_json::from_value(
                event
                    .get("full209_terminal_peer")
                    .cloned()
                    .unwrap_or(Value::Null),
            )?,
            terminal: serde_json::from_value(event["terminal"].clone())?,
            output_directory: directory.into(),
        };
        let claim: Claim = serde_json::from_value(old["assembly204_recovery"].clone())?;
        terminal_projection(&x, old, &claim)?
    } else {
        ensure!(
            event.get("action").is_none(),
            "204 saved event action differs"
        );
        let x = Prepare {
            schema: String::new(),
            original_plan,
            previous_fleet,
            observer,
            claim: serde_json::from_value(event["claim"].clone())?,
            output_directory: directory.into(),
        };
        let frame = frame.context("204 saved event frame missing")?;
        ensure!(
            frame["schema"] == "jetstreamer-epoch204-assembly-recovery-work-v1"
                && frame["epoch"] == 204
                && frame["epoch_started_unix_millis"] == ORIGIN
                && frame["recovery_plan"] == private157::binding(&x.claim.recovery_plan)
                && frame["launch"] == private157::binding(&x.claim.launch)
                && frame["actor_launch"] == private157::binding(&x.claim.actor_launch)
                && frame["previous_fleet"] == private157::binding(&x.previous_fleet)
                && frame["observer"] == private157::binding(&x.observer)
                && frame["sampled_at_utc"] == event["sampled_at_utc"],
            "204 saved event frame differs"
        );
        active_projection(&x, old, previous, frame)?
    };
    Ok(expected)
}
pub(super) fn prepare_terminal(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: TerminalPrepare = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-terminal-prepare-spec-v1",
        "204 terminal prepare spec"
    );
    private(&x.output_directory)?;
    let t = read(&x.terminal)?;
    if terminal_context_join(&x, &t)? {
        let context = context::WorkContext::new(
            x.previous_fleet.clone(),
            x.observer.clone(),
            x.observer_history.clone(),
        )?
        .with_full209_terminal_peer(x.full209_terminal_peer.clone());
        ownership::no_overlap_work(&context)?;
    } else {
        let context = AcceptedContext {
            fleet: x.previous_fleet.clone(),
            observer: x.observer.clone(),
        };
        ownership::no_overlap(&context, None)?;
    }
    let old = bound_json(&x.original_plan)?;
    let prior = bound_json(&x.previous_fleet)?;
    let mut next = terminal_derivative(&x, &old, &prior)?;
    ensure!(
        unit(s(&t, "unit")?)? == t["current_unit"],
        "204 terminal owner changed before handoff"
    );
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sampled = ownership::millis_utc(
        at.checked_mul(1000)
            .context("204 terminal event clock overflow")?,
    )?;
    let event = write(
        &x.output_directory.join("event.json"),
        &json!({"schema":EVENT_SCHEMA,"action":"terminal",
        "original_plan":x.original_plan,"previous_fleet":x.previous_fleet,"observer":x.observer,"observer_history":x.observer_history,"full209_terminal_peer":x.full209_terminal_peer,"terminal":x.terminal,
        "sampled_at_utc":sampled,"metadata_only":true,"resource_samples_taken":0,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    next["metadata_event"] = private157::binding(&event);
    write(&x.output_directory.join("plan.json"), &next)?;
    Ok(())
}
fn terminal_context_join(x: &TerminalPrepare, terminal: &Value) -> Result<bool> {
    let assembly = terminal.get("assembly_success_origin");
    let downstream = terminal.get("downstream_success_origin");
    ensure!(
        assembly.is_none() || downstream.is_none(),
        "204 terminal has ambiguous success origins"
    );
    if let Some(origin) = assembly.or(downstream) {
        ensure!(
            (if assembly.is_some() {
                terminal["unit"] == UNIT
            } else {
                terminal["unit"] != UNIT && x.full209_terminal_peer.is_none()
            }) && terminal["result"] == "natural_success"
                && origin["context"]["fleet"] == private157::binding(&x.previous_fleet)
                && origin["context"]["observer"] == private157::binding(&x.observer)
                && origin["observer_history"] == serde_json::to_value(&x.observer_history)?
                && origin.get("full209_terminal_peer").unwrap_or(&Value::Null)
                    == &serde_json::to_value(&x.full209_terminal_peer)?,
            "204 terminal event changed its authenticated success observation context"
        );
        return Ok(true);
    }
    ensure!(
        x.observer_history.is_empty() && x.full209_terminal_peer.is_none(),
        "204 observer refresh requires exact assembly success origin"
    );
    Ok(false)
}

pub(in crate::fleet) fn terminal_row(
    bound: &BoundFile,
    current: &BTreeMap<String, Value>,
) -> Result<Value> {
    let t = read(bound)?;
    let name = s(&t, "unit")?;
    let iid = s(&t, "invocation_id")?;
    if t["result"] == "natural_success" {
        ownership::validate_success_terminal(&t, name, iid)?;
    } else {
        ownership::validate_failure_terminal(&t)?;
    }
    let unit = current
        .get(name)
        .context("204 terminal current owner omitted")?;
    ensure!(
        is_idle(unit) && (unit["InvocationID"] == iid || unit["InvocationID"] == ""),
        "204 terminal owner live/replaced"
    );
    for (name, row) in current.iter().filter(|(name, _)| scope(name, 204, 204)) {
        ensure!(
            is_idle(row),
            "204 terminal overlaps live recovery owner: {name}"
        );
    }
    Ok(
        json!({"epoch":204,"phase":"assembly-recovery204-terminal","live":false,"positive_inactivity_confirmed":true,
        "unit":unit,"terminal":bound,"result":t["result"],"current_sidecar_eta_valid":false,"authority":denied()}),
    )
}

#[cfg(test)]
mod terminal_context_tests {
    use super::*;
    fn binding(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/fixture").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn spec() -> Value {
        json!({"schema":"jetstreamer-epoch204-assembly-recovery-terminal-prepare-spec-v1",
            "original_plan":binding("plan.json"),"previous_fleet":binding("fleet417.json"),
            "observer":binding("observer418.json"),"terminal":binding("terminal.json"),
            "output_directory":"/var/lib/jetstreamer/horizon-204-assembly-fleet-event-terminal-test"})
    }
    #[test]
    fn terminal_prepare_defaults_history_and_binds_exact_success_capture_context() {
        let x: TerminalPrepare = serde_json::from_value(spec()).unwrap();
        assert!(x.observer_history.is_empty());
        let t = json!({"unit":UNIT,"result":"natural_success","assembly_success_origin":{
            "context":{"fleet":x.previous_fleet,"observer":x.observer},"observer_history":[]}});
        assert!(terminal_context_join(&x, &t).unwrap());
        for path in [
            "/assembly_success_origin/context/fleet/sha256",
            "/assembly_success_origin/context/observer/sha256",
        ] {
            let mut changed = t.clone();
            *changed.pointer_mut(path).unwrap() = json!("b".repeat(64));
            assert!(terminal_context_join(&x, &changed).is_err());
        }
        for (key, value) in [("unit", json!(OLD_UNIT)), ("result", json!("failed"))] {
            let mut changed = t.clone();
            changed[key] = value;
            assert!(terminal_context_join(&x, &changed).is_err());
        }
        let mut changed = t.clone();
        changed["assembly_success_origin"]["observer_history"] =
            json!([binding("intermediate.json")]);
        assert!(terminal_context_join(&x, &changed).is_err());
        assert!(!terminal_context_join(&x, &json!({"result":"failed"})).unwrap());
        let mut nonempty = spec();
        nonempty["observer_history"] = json!([binding("intermediate.json")]);
        let with_history: TerminalPrepare = serde_json::from_value(nonempty).unwrap();
        assert!(terminal_context_join(&with_history, &json!({"result":"failed"})).is_err());
    }
    #[test]
    fn full209_peer_terminal_join_requires_the_identical_saved_proof_and_assembly_scope() {
        let mut raw = spec();
        let peer = json!({"launch":binding("209-launch.json"),"manager_journal":binding("209-manager.jsonl"),"cohort_receipt":binding("209-cohort.json")});
        raw["full209_terminal_peer"] = peer.clone();
        let x: TerminalPrepare = serde_json::from_value(raw).unwrap();
        let terminal = json!({"unit":UNIT,"result":"natural_success","assembly_success_origin":{
            "context":{"fleet":x.previous_fleet,"observer":x.observer},"observer_history":[],"full209_terminal_peer":peer}});
        assert!(terminal_context_join(&x, &terminal).unwrap());
        let mut changed = terminal.clone();
        changed["assembly_success_origin"]["full209_terminal_peer"]["manager_journal"]["sha256"] =
            json!("f".repeat(64));
        assert!(terminal_context_join(&x, &changed).is_err());
        changed = terminal;
        let origin = changed["assembly_success_origin"].take();
        changed["downstream_success_origin"] = origin;
        changed
            .as_object_mut()
            .unwrap()
            .remove("assembly_success_origin");
        changed["unit"] = json!(downstream::Stage::Full.unit());
        assert!(terminal_context_join(&x, &changed).is_err());
    }
    #[test]
    fn downstream_terminal_handoff_reuses_its_exact_refreshed_origin() {
        let mut raw = spec();
        raw["observer_history"] = json!([binding("middle-observer.json")]);
        let x: TerminalPrepare = serde_json::from_value(raw).unwrap();
        let terminal = json!({"unit":downstream::Stage::Full.unit(),"result":"natural_success","downstream_success_origin":{
            "context":{"fleet":x.previous_fleet,"observer":x.observer},"observer_history":x.observer_history}});
        assert!(terminal_context_join(&x, &terminal).unwrap());
        let mut changed = terminal.clone();
        changed["downstream_success_origin"]["observer_history"] = json!([]);
        assert!(terminal_context_join(&x, &changed).is_err());
        changed = terminal;
        changed["result"] = json!("failed");
        assert!(terminal_context_join(&x, &changed).is_err());
    }
    #[test]
    fn saved_terminal_projection_retains_explicit_history_without_fabricated_frames() {
        let previous = json!({"plan":"/fixture/plan.json","plan_sha256":"a".repeat(64)});
        let claim = json!({"epoch":204,"recovery_plan":binding("recovery.json"),"admission":binding("admission.json"),
            "launch":binding("launch.json"),"actor_launch":binding("launch.json"),"frame":binding("frame.json"),"eta_policy":binding("eta.json")});
        let old = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":201,"last_epoch":300,
            "assembly204_recovery":claim,"unrelated_guard":123,"assembly204_recovery_history":[]});
        let mut event = json!({"action":"terminal","original_plan":binding("plan.json"),"previous_fleet":binding("fleet417.json"),
            "observer":binding("observer419.json"),"observer_history":[binding("observer418.json")],"terminal":binding("terminal.json")});
        let projected =
            saved_event_plan(&event, &old, &previous, None, Path::new("/fixture/event")).unwrap();
        assert!(projected["assembly204_recovery"].is_null());
        assert_eq!(projected["unrelated_guard"], 123);
        assert_eq!(projected["assembly204_recovery_history"], json!([claim]));
        event["observer_history"] = json!([{"path":"/fixture/missing-digest.json"}]);
        assert!(
            saved_event_plan(&event, &old, &previous, None, Path::new("/fixture/event")).is_err()
        );
    }
}
