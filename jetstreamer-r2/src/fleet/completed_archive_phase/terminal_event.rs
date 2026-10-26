//! Reconcile a real terminal delivery phase before admitting its successor.
//! No live owner or intermediate accepted fleet is manufactured.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-completed209-phase-terminal-event-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    terminal: BoundFile,
    output_directory: PathBuf,
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed209 terminal event text absent: {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed209 terminal event integer absent: {k}"))
}
fn scope(r: &Request) -> Result<()> {
    ensure!(
        r.schema == "jetstreamer-completed209-phase-terminal-event-request-v1"
            && r.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && r.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-generic209-terminal-event-")),
        "completed209 terminal event request/output scope differs"
    );
    resource_audit::private_directory(&r.output_directory)
}
fn denied() -> Value {
    json!({"live_owner_claimed":false,"resource_samples_taken":0,"replay_launch_authorized":false,
    "archive_completion_claimed":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn evidence(event: &Value) -> Result<(Request, Value, Spec)> {
    ensure!(
        event["schema"] == SCHEMA && event["epoch"] == 209 && event["authority"] == denied(),
        "completed209 terminal event schema/authority differs"
    );
    let r: Request =
        serde_json::from_value(read(&serde_json::from_value(event["request"].clone())?)?)?;
    scope(&r)?;
    let proof = read(&r.terminal)?;
    let (s, _) = terminal::validate(&proof)?;
    ensure!(
        event["terminal"] == private157::binding(&r.terminal)
            && event["observer"] == private157::binding(&r.observer)
            && event["previous_fleet"] == private157::binding(&r.previous_fleet)
            && event["phase"] == s.phase.name()
            && event["original_invocation_id"] == proof["original_invocation_id"],
        "completed209 terminal event changed original phase/input bindings"
    );
    Ok((r, proof, s))
}
fn projected(previous: &Value, proof: &Value, s: &Spec) -> Result<Value> {
    let mut view = previous.clone();
    terminal::project_one(&mut view, proof, s)?;
    Ok(view)
}
fn gate(old: &Value, proof: &BoundFile) -> Result<Value> {
    ensure!(
        matches!(
            old["state"].as_str(),
            Some("blocked-qualification" | "failed-needs-repair" | "post-replay-pipeline")
        ),
        "completed209 terminal event cannot promote readiness"
    );
    let mut result = old.clone();
    result["state"] = json!("post-replay-pipeline");
    let rows = result["evidence"]
        .as_array_mut()
        .context("completed209 terminal old gate evidence missing")?;
    let b = private157::binding(proof);
    if !rows.contains(&b) {
        rows.push(b);
    }
    Ok(result)
}
fn delta(old: &Value, new: &Value, r: &Request, s: &Spec) -> Result<()> {
    let mut expected = old.clone();
    expected["observer"] = private157::binding(&r.observer);
    expected["previous_fleet"] = private157::binding(&r.previous_fleet);
    expected["metadata_event"] = json!({"path":r.output_directory.join("event.json"),"sha256":new["metadata_event"]["sha256"]});
    expected["admission_transition_guard"] = Value::Null;
    expected["output"] = json!(r.output_directory.join("fleet.json"));
    expected["gates"]["209"] = gate(&old["gates"]["209"], &r.terminal)?;
    let tracked = expected["tracked_units"]
        .as_array_mut()
        .context("completed209 terminal tracked census missing")?;
    for name in [&s.units[s.phase.name()], &s.guard_units[s.phase.name()]] {
        if !tracked.iter().any(|v| v == name) {
            tracked.push(json!(name));
        }
    }
    ensure!(
        *new == expected,
        "completed209 terminal event changed unrelated gates, owners, claims or policy"
    );
    Ok(())
}
pub(super) fn prepare() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("prepare-completed209-terminal-event")?;
    let r: Request = serde_json::from_value(read(&binding)?)?;
    scope(&r)?;
    ensure!(
        fs::read_dir(&r.output_directory)?.next().is_none(),
        "completed209 terminal event attempt is not empty"
    );
    let proof = read(&r.terminal)?;
    let (s, _) = terminal::validate(&proof)?;
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let event = json!({"schema":SCHEMA,"epoch":209,"phase":s.phase,"request":binding,"issuer_sha256":self_sha,
        "terminal":r.terminal,"observer":r.observer,"previous_fleet":r.previous_fleet,"original_invocation_id":proof["original_invocation_id"],
        "recorded_unix_seconds":at,"sampled_at_utc":publication203::utc(at)?,"authority":denied()});
    private157::immutable_receipt(&r.output_directory.join("event.json"), &event)?;
    let eb: BoundFile = serde_json::from_value(private157::file_binding(
        &r.output_directory.join("event.json"),
    )?)?;
    let previous = read(&r.previous_fleet)?;
    let mut p = read(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    p["observer"] = private157::binding(&r.observer);
    p["previous_fleet"] = private157::binding(&r.previous_fleet);
    p["metadata_event"] = private157::binding(&eb);
    p["admission_transition_guard"] = Value::Null;
    p["output"] = json!(r.output_directory.join("fleet.json"));
    p["gates"]["209"] = gate(&p["gates"]["209"], &r.terminal)?;
    let tracked = p["tracked_units"]
        .as_array_mut()
        .context("completed209 terminal tracked census missing")?;
    for name in [&s.units[s.phase.name()], &s.guard_units[s.phase.name()]] {
        if !tracked.iter().any(|v| v == name) {
            tracked.push(json!(name));
        }
    }
    let pb = r.output_directory.join("fleet-plan.json");
    private157::immutable_receipt(&pb, &p)?;
    let bound: BoundFile = serde_json::from_value(private157::file_binding(&pb)?)?;
    let typed: Plan = serde_json::from_value(p)?;
    predecessor(
        &previous,
        &typed,
        &bound,
        &event,
        text(&read(&r.observer)?, "recorded_at_utc")?,
        at,
    )?;
    let mut names: BTreeSet<String> = previous["unit_census"]
        .as_object()
        .context("completed209 terminal complete previous census missing")?
        .keys()
        .cloned()
        .collect();
    names.extend(typed.tracked_units.iter().cloned());
    census_check(&previous, &census(&names, 201, 300)?, &event)
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    pb: &BoundFile,
    event: &Value,
    sample: &str,
    at: u64,
) -> Result<()> {
    let (r, proof, s) = evidence(event)?;
    let old_observer = BoundFile {
        path: text(previous, "observer_receipt")?.into(),
        sha256: text(previous, "observer_sha256")?.into(),
    };
    let historical = read(&old_observer)?;
    full209_event::accepted(
        &projected(previous, &proof, &s)?,
        &old_observer,
        &historical,
    )?;
    let o = read(&r.observer)?;
    full209_event::late_capture::chain(&r.observer, &o, &old_observer, &historical)?;
    let resource = utc_seconds(text(&o, "recorded_at_utc")?)?;
    let recorded = number(event, "recorded_unix_seconds")?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && p.observer == r.observer
            && p.previous_fleet.as_ref() == Some(&r.previous_fleet)
            && sample == text(&o, "recorded_at_utc")?
            && resource <= recorded
            && recorded <= at
            && at - resource <= 1800
            && at - recorded <= 300
            && recorded > number(previous, "recorded_unix_seconds")?
            && event["sampled_at_utc"] == publication203::utc(recorded)?
            && pb.path == r.output_directory.join("fleet-plan.json")
            && p.output == r.output_directory.join("fleet.json")
            && p.metadata_event
                .as_ref()
                .is_some_and(|b| b.path == r.output_directory.join("event.json")
                    && read(b).is_ok_and(|v| v == *event)),
        "completed209 terminal event lost its complete fresh predecessor/request"
    );
    let old = read(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    delta(&old, &read(pb)?, &r, &s)
}
pub(super) fn census_check(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    event: &Value,
) -> Result<()> {
    let (_, proof, s) = evidence(event)?;
    let view = projected(previous, &proof, &s)?;
    let mut peers = current.clone();
    let guard = &s.guard_units[s.phase.name()];
    idle(
        peers
            .get(guard)
            .context("completed209 terminal guard omitted")?,
    )?;
    peers.remove(guard);
    let name = &s.units[s.phase.name()];
    terminal::owner_matches(
        &s,
        &proof["startup_release_contents"],
        current
            .get(name)
            .context("completed209 terminal owner omitted")?,
    )?;
    maintenance_capacity::current_owners(&view, &peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed209_terminal_event_keeps_live_claim_history_and_unrelated_policy_unchanged() {
        let s = super::super::tests::fixture(Phase::Plugin);
        let b = BoundFile {
            path: "/sealed/terminal.json".into(),
            sha256: "a".repeat(64),
        };
        let r = Request {
            schema: "jetstreamer-completed209-phase-terminal-event-request-v1".into(),
            observer: b.clone(),
            previous_fleet: b.clone(),
            terminal: b,
            output_directory: "/var/lib/jetstreamer/horizon-generic209-terminal-event-test".into(),
        };
        let old = json!({"tracked_units":["peer.service"],"pipeline_claims":[{"epoch":209,"original_live_launch":"retained"}],
            "gates":{"209":{"state":"post-replay-pipeline","evidence":["original"]}},"peer":{"invocation_id":"b".repeat(32)}});
        let mut new = old.clone();
        new["observer"] = private157::binding(&r.observer);
        new["previous_fleet"] = private157::binding(&r.previous_fleet);
        new["metadata_event"] =
            json!({"path":r.output_directory.join("event.json"),"sha256":"c".repeat(64)});
        new["admission_transition_guard"] = Value::Null;
        new["output"] = json!(r.output_directory.join("fleet.json"));
        new["gates"]["209"] = gate(&old["gates"]["209"], &r.terminal).unwrap();
        new["tracked_units"] = json!(["peer.service", s.units["plugin"], s.guard_units["plugin"]]);
        delta(&old, &new, &r, &s).unwrap();
        for (pointer, value) in [
            ("/pipeline_claims", json!([])),
            ("/peer/invocation_id", json!("0".repeat(32))),
            ("/gates/209/state", json!("remote-ready")),
        ] {
            let mut bad = new.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(delta(&old, &bad, &r, &s).is_err(), "{pointer}");
        }
    }
    #[test]
    fn completed209_terminal_event_request_cannot_claim_activity_or_skip_observation() {
        let b = json!({"path":"/sealed/metadata.json","sha256":"a".repeat(64)});
        let mut r = json!({"schema":"jetstreamer-completed209-phase-terminal-event-request-v1","observer":b,"previous_fleet":b,"terminal":b,
            "output_directory":"/var/lib/jetstreamer/horizon-generic209-terminal-event-test"});
        assert!(serde_json::from_value::<Request>(r.clone()).is_ok());
        r["live_owner_claimed"] = json!(true);
        assert!(serde_json::from_value::<Request>(r).is_err());
        assert_eq!(denied()["live_owner_claimed"], false);
        assert_eq!(denied()["archive_completion_claimed"], false);
    }
}
