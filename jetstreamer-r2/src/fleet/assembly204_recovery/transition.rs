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
pub(super) fn prepare_terminal(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: TerminalPrepare = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-terminal-prepare-spec-v1",
        "204 terminal prepare spec"
    );
    private(&x.output_directory)?;
    let context = Context {
        fleet: x.previous_fleet.clone(),
        observer: x.observer.clone(),
    };
    ownership::no_overlap(&context, None)?;
    let old = bound_json(&x.original_plan)?;
    let prior = bound_json(&x.previous_fleet)?;
    let mut next = terminal_derivative(&x, &old, &prior)?;
    let t = read(&x.terminal)?;
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
        "original_plan":x.original_plan,"previous_fleet":x.previous_fleet,"observer":x.observer,"terminal":x.terminal,
        "sampled_at_utc":sampled,"metadata_only":true,"resource_samples_taken":0,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    next["metadata_event"] = private157::binding(&event);
    write(&x.output_directory.join("plan.json"), &next)?;
    Ok(())
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
