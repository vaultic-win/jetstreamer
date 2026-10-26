//! A captured epoch209 delivery child may join one accepted resource sample. This is
//! metadata ownership, never replay, archive readiness, or capacity credit.
use super::*;
pub(super) mod late_capture;
mod status;
pub(in crate::fleet) use status::{publish, status_matches};
pub(in crate::fleet) const EVENT_SCHEMA: &str = "jetstreamer-completed209-full-captured-event-v1";
const DELIVERY_EVENT: &str = "jetstreamer-completed209-delivery-captured-event-v1";
const DELIVERY_REQUEST: &str = "jetstreamer-completed209-delivery-event-request-v1";
pub(super) fn is_event(v: &Value) -> bool {
    v["schema"] == EVENT_SCHEMA || v["schema"] == DELIVERY_EVENT
}
fn phase(l: &Value) -> Result<Phase> {
    Ok(serde_json::from_value(l["phase"].clone())?)
}
fn claim_phase(p: Phase) -> &'static str {
    match p {
        Phase::Full => "full-verification",
        Phase::Plugin => "plugin-verification",
        Phase::Upload => "upload-readback",
    }
}
const REQUEST: &str = "jetstreamer-completed209-full-event-request-v1";
const MAX_EVENT_AGE: u64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    observer: BoundFile,
    previous_fleet: BoundFile,
    launch: BoundFile,
    output_directory: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn denied() -> Value {
    json!({"resource_samples_taken":0,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"archive_completion_claimed":false,
        "capacity_credit_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false})
}
fn capture_shape(l: &Value) -> Result<()> {
    ensure!(
        l["schema"] == "jetstreamer-completed-archive-phase-launch-v1"
            && l["epoch"] == 209
            && (l["phase"] == "full"
                || l["phase_spec_contents"]["launcher_transition"].is_object())
            && l["child_execution_authorized"] == false
            && l["publication_authorized"] == false
            && l["remote_mutations"] == false
            && l["r2_mutations"] == false
            && pipeline_scope(claim_phase(phase(l)?), string(l, "unit")?) == Some(209)
            && l["owner"]["Id"] == l["unit"]
            && l["owner"]["InvocationID"] == l["invocation_id"]
            && l["owner"]["NRestarts"] == "0"
            && l["owner"]["ActiveState"] == "active"
            && l["owner"]["SubState"] == "running"
            && l["process"]["source_read_only_mount"] == true
            && l["startup_release"].is_object()
            && l["startup_release_contents"]["schema"] == barrier::RELEASE,
        "completed209 event requires the genuine captured delivery child, not a terminal proof or waiter"
    );
    Ok(())
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed209 event missing text: {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed209 event missing integer: {k}"))
}
fn claim(binding: &BoundFile, l: &Value) -> Result<PipelineClaim> {
    capture_shape(l)?;
    Ok(PipelineClaim {
        epoch: 209,
        phase: claim_phase(phase(l)?).into(),
        unit: string(l, "unit")?.into(),
        invocation_id: string(l, "invocation_id")?.into(),
        expected_exec_start: string(&l["effective_unit"], "ExecStart")?.into(),
        evidence: vec![binding.clone()],
    })
}
fn admitted_resource(a: &Value, s: &Spec) -> Result<()> {
    ensure!(
        a["capacity"]["resource_basis"] == s.resource_basis,
        "completed209 event changed the actual admitted capacity context"
    );
    Ok(())
}
fn checked_launch(binding: &BoundFile) -> Result<(PipelineClaim, Value, Spec, Value)> {
    let l = read(binding)?;
    let c = claim(binding, &l)?;
    let (actual, saved, s, a) = peer::claim_launch(&c)?;
    ensure!(
        actual == *binding && saved == l && s.epoch == 209 && s.phase == phase(&l)?,
        "completed209 capture differs from its qualified saved launch/control proofs"
    );
    admitted_resource(&a, &s)?;
    Ok((c, saved, s, a))
}
fn owner_shape(l: &Value, u: &Value) -> Result<()> {
    for k in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        ensure!(
            !l["owner"][k].is_null() && u[k] == l["owner"][k],
            "completed209 live child changed: {k}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            string(&l["owner"], "ExecStart")?,
            string(u, "ExecStart")?
        ),
        "completed209 live child command changed"
    );
    Ok(())
}
fn live(c: &PipelineClaim, l: &Value) -> Result<Value> {
    let proof = peer::captured_live(c)?;
    let u = proof["owner"].clone();
    owner_shape(l, &u)?;
    native_shape(l, &proof["process"])?;
    Ok(u)
}
fn native_shape(l: &Value, p: &Value) -> Result<()> {
    ensure!(
        p["source_read_only_mount"] == true,
        "completed209 current archive mount is writable"
    );
    for k in [
        "pid",
        "start_ticks",
        "native_start_clock",
        "executable",
        "executable_sha256",
        "cmdline",
        "cgroup",
        "native_limits",
    ] {
        ensure!(
            !p[k].is_null() && p[k] == l["process"][k],
            "completed209 native child/control proof changed: {k}"
        );
    }
    Ok(())
}
fn event_clock(previous: &Value, o: &Value, l: &Value, at: u64) -> Result<u64> {
    let resource = utc_seconds(string(o, "recorded_at_utc")?)?;
    let captured = number(l, "captured_unix_seconds")?;
    let started = number(&l["process"]["native_start_clock"], "started_unix_seconds")?;
    ensure!(
        resource <= at
            && at - resource <= 1800
            && captured > resource
            && captured <= at
            && at - captured <= MAX_EVENT_AGE
            && started <= captured
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < captured),
        "completed209 event is stale, backwards, or predates its actual native child"
    );
    Ok(captured)
}
pub(super) fn accepted(previous: &Value, observer: &BoundFile, o: &Value) -> Result<()> {
    ensure!(
        previous["schema"] == super::super::SCHEMA
            && previous["first_epoch"] == 201
            && previous["last_epoch"] == 300
            && previous["observer_receipt"].as_str() == observer.path.to_str()
            && previous["observer_sha256"] == observer.sha256
            && previous["sampled_at_utc"] == o["recorded_at_utc"]
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous["inventory"]["anomalies"] == 0
            && !previous["active"]
                .as_array()
                .context("completed209 prior roster missing")?
                .iter()
                .any(|r| r["epoch"] == 209),
        "completed209 event must retain the complete accepted observation and cannot replace an active209 owner"
    );
    Ok(())
}
fn accepted_child(previous: &Value, observer: &BoundFile, o: &Value, l: &Value) -> Result<()> {
    if phase(l)? == Phase::Full {
        return accepted(previous, observer, o);
    }
    let s: Spec = serde_json::from_value(read(&serde_json::from_value(l["phase_spec"].clone())?)?)?;
    let (view, _) = terminal::previous_view(previous, &s)?;
    accepted(&view, observer, o)
}
fn event_launch(event: &Value) -> Result<(PipelineClaim, Value, Spec, Value)> {
    ensure!(
        is_event(event) && event["epoch"] == 209 && event["authority"] == denied(),
        "completed209 event scope/authority differs"
    );
    let b: BoundFile = serde_json::from_value(event["launch"].clone())?;
    let result = checked_launch(&b)?;
    ensure!(
        event["phase"] == result.0.phase
            && (event["schema"] == DELIVERY_EVENT || result.2.phase == Phase::Full)
            && event["claim"] == serde_json::to_value(&result.0)?
            && event["recorded_unix_seconds"] == result.1["captured_unix_seconds"]
            && utc_seconds(string(event, "sampled_at_utc")?)?
                == number(&result.1, "captured_unix_seconds")?,
        "completed209 event borrowed a different capture or clock"
    );
    Ok(result)
}
fn output_scope(path: &Path) -> Result<()> {
    resource_audit::private_directory(path)?;
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-generic209-full-event-")
                    || n.starts_with("horizon-generic209-delivery-event-")),
        "completed209 event needs its dedicated private namespace"
    );
    Ok(())
}
fn private_output(path: &Path) -> Result<()> {
    output_scope(path)?;
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "completed209 event attempt is not empty"
    );
    Ok(())
}
pub(in crate::fleet) fn prepare() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "completed209 event preparation requires root"
    );
    let (binding, self_sha) = publication203::parsed_args("prepare-completed209-full-event")?;
    let r: Request = serde_json::from_value(read(&binding)?)?;
    ensure!(
        matches!(r.schema.as_str(), REQUEST | DELIVERY_REQUEST),
        "completed209 event request schema differs"
    );
    private_output(&r.output_directory)?;
    let previous = read(&r.previous_fleet)?;
    let o = read(&r.observer)?;
    let (c, l, s, a) = checked_launch(&r.launch)?;
    let late = late_capture::context(&previous, &r.observer, &o, &l, &a, &c)?;
    ensure!(
        (late || a["capacity"]["resource_basis"]["observer"] == private157::binding(&r.observer))
            && a["capacity"]["resource_basis"]["fleet"] == private157::binding(&r.previous_fleet),
        "completed209 event substituted the child's admitted resource context"
    );
    let captured = event_clock(&previous, &o, &l, now()?)?;
    live(&c, &l)?;
    let event = json!({"schema":if s.phase == Phase::Full {EVENT_SCHEMA} else {DELIVERY_EVENT},"epoch":209,"phase":c.phase,
        "request":binding,"issuer_sha256":self_sha,"observer":r.observer,"previous_fleet":r.previous_fleet,
        "output_directory":r.output_directory,
        "launch":r.launch,"claim":c,"recorded_unix_seconds":captured,
        "sampled_at_utc":publication203::utc(captured)?,"authority":denied()});
    let event_path = r.output_directory.join("event.json");
    private157::immutable_receipt(&event_path, &event)?;
    let event_bound: BoundFile = serde_json::from_value(private157::file_binding(&event_path)?)?;
    let old_binding: BoundFile =
        serde_json::from_value(json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}))?;
    let mut plan = read(&old_binding)?;
    plan.as_object_mut()
        .context("completed209 prior plan object missing")?
        .entry("pipeline_claims")
        .or_insert_with(|| json!([]));
    let claims = plan["pipeline_claims"]
        .as_array_mut()
        .context("completed209 prior claim list missing")?;
    ensure!(
        !claims.iter().any(|v| v["unit"] == c.unit),
        "completed209 owner already registered"
    );
    claims.push(serde_json::to_value(&c)?);
    plan["gates"]["209"] = pipeline_gate(&plan["gates"]["209"], &c)?;
    let tracked = plan["tracked_units"]
        .as_array_mut()
        .context("completed209 tracked roster missing")?;
    for name in [&c.unit, &s.guard_units[s.phase.name()]] {
        if !tracked.iter().any(|n| n.as_str() == Some(name.as_str())) {
            tracked.push(json!(name));
        }
    }
    if late {
        plan["observer"] = private157::binding(&r.observer);
    }
    plan["previous_fleet"] = private157::binding(&r.previous_fleet);
    plan["metadata_event"] = private157::binding(&event_bound);
    plan["admission_transition_guard"] = Value::Null;
    plan["output"] = json!(r.output_directory.join("fleet.json"));
    let plan_path = r.output_directory.join("fleet-plan.json");
    private157::immutable_receipt(&plan_path, &plan)?;
    let pb: BoundFile = serde_json::from_value(private157::file_binding(&plan_path)?)?;
    let typed: Plan = serde_json::from_value(plan)?;
    event_predecessor(
        &previous,
        &typed,
        &pb,
        &event,
        string(&o, "recorded_at_utc")?,
        now()?,
    )?;
    let mut names = previous["unit_census"]
        .as_object()
        .context("completed209 complete census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c.unit.clone());
    names.insert(s.guard_units[s.phase.name()].clone());
    event_census(&previous, &census(&names, 201, 300)?, &event)?;
    live(&c, &l)?;
    Ok(())
}
pub(in crate::fleet) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    pb: &BoundFile,
    event: &Value,
    sample: &str,
    at: u64,
) -> Result<()> {
    let (c, l, s, a) = event_launch(event)?;
    let o = read(&p.observer)?;
    let late = late_capture::context(previous, &p.observer, &o, &l, &a, &c)?;
    let t = event_clock(previous, &o, &l, at)?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| event["previous_fleet"] == private157::binding(b))
            && event["observer"] == private157::binding(&p.observer)
            && sample == string(&o, "recorded_at_utc")?
            && (late || a["capacity"]["resource_basis"]["observer"] == event["observer"])
            && a["capacity"]["resource_basis"]["fleet"] == event["previous_fleet"]
            && number(event, "recorded_unix_seconds")? == t,
        "completed209 event lost its exact admitted predecessor/observation"
    );
    let request: Request =
        serde_json::from_value(read(&serde_json::from_value(event["request"].clone())?)?)?;
    ensure!(
        matches!(request.schema.as_str(), REQUEST | DELIVERY_REQUEST)
            && event["observer"] == private157::binding(&request.observer)
            && event["previous_fleet"] == private157::binding(&request.previous_fleet)
            && event["launch"] == private157::binding(&request.launch)
            && event["output_directory"] == serde_json::to_value(&request.output_directory)?
            && p.metadata_event
                .as_ref()
                .is_some_and(|b| b.path == request.output_directory.join("event.json"))
            && pb.path == request.output_directory.join("fleet-plan.json")
            && p.output == request.output_directory.join("fleet.json"),
        "completed209 event request/output namespace changed"
    );
    output_scope(&request.output_directory)?;
    let old = read(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    let new = read(pb)?;
    plan_delta(
        &old,
        &new,
        &c,
        &s.guard_units[s.phase.name()],
        if late { Some(&p.observer) } else { None },
    )?;
    let old_claims: Vec<PipelineClaim> = serde_json::from_value(
        old.get("pipeline_claims")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )?;
    ensure!(
        p.pipeline_claims.len() == old_claims.len() + 1
            && p.pipeline_claims.contains(&c)
            && old_claims.iter().all(|v| p.pipeline_claims.contains(v))
            && !old_claims.iter().any(|v| v.unit == c.unit),
        "completed209 event changed claim history"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.insert(c.unit.clone());
    tracked.insert(s.guard_units[s.phase.name()].clone());
    ensure!(
        tracked == p.tracked_units.iter().cloned().collect(),
        "completed209 event changed unrelated tracked owners"
    );
    ensure!(
        p.metadata_event
            .as_ref()
            .is_some_and(|b| read(b).is_ok_and(|v| v == *event)),
        "completed209 event differs from the registered immutable event"
    );
    Ok(())
}
fn plan_delta(
    old: &Value,
    new: &Value,
    c: &PipelineClaim,
    guard: &str,
    observer: Option<&BoundFile>,
) -> Result<()> {
    let old_claims = old
        .get("pipeline_claims")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut expected = old_claims
        .as_array()
        .context("completed209 prior claims are not an array")?
        .clone();
    ensure!(
        !expected.iter().any(|v| v["unit"] == c.unit),
        "completed209 owner already in history"
    );
    expected.push(serde_json::to_value(c)?);
    ensure!(
        new["pipeline_claims"] == json!(expected),
        "completed209 pipeline history reordered or changed"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.insert(c.unit.clone());
    tracked.insert(guard.into());
    let actual: Vec<String> = serde_json::from_value(new["tracked_units"].clone())?;
    ensure!(
        actual.len() == tracked.len() && actual.into_iter().collect::<BTreeSet<_>>() == tracked,
        "completed209 tracked census changed or duplicated"
    );
    let mut left = old.clone();
    if let Some(b) = observer {
        ensure!(
            new["observer"] == private157::binding(b),
            "completed209 late event substituted observer"
        );
        left["observer"] = private157::binding(b);
    }
    let mut right = new.clone();
    let expected_gate = pipeline_gate(&old["gates"]["209"], c)?;
    ensure!(
        new["gates"]["209"] == expected_gate,
        "completed209 event changed qualification history or claimed archive readiness"
    );
    left["gates"]["209"] = expected_gate;
    for k in [
        "pipeline_claims",
        "tracked_units",
        "previous_fleet",
        "metadata_event",
        "admission_transition_guard",
        "output",
    ] {
        left.as_object_mut().context("old plan object")?.remove(k);
        right.as_object_mut().context("new plan object")?.remove(k);
    }
    ensure!(
        left == right,
        "completed209 event changed unrelated policy, gates, history or ownership"
    );
    Ok(())
}
fn pipeline_gate(old: &Value, c: &PipelineClaim) -> Result<Value> {
    ensure!(
        matches!(
            old["state"].as_str(),
            Some("blocked-qualification" | "failed-needs-repair" | "post-replay-pipeline")
        ),
        "completed209 event cannot replace a ready or otherwise unqualified gate"
    );
    let mut gate = old.clone();
    // The generic pipeline validator requires this observational classification.
    // No archive, verifier, plugin, upload or sidecar gate is promoted by it.
    gate["state"] = json!("post-replay-pipeline");
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("completed209 prior gate evidence missing")?;
    for b in &c.evidence {
        let v = serde_json::to_value(b)?;
        if !evidence.contains(&v) {
            evidence.push(v);
        }
    }
    Ok(gate)
}
pub(in crate::fleet) fn event_census(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    event: &Value,
) -> Result<()> {
    let (c, l, s, _) = event_launch(event)?;
    let (previous_view, terminal_guards) = if s.phase == Phase::Full {
        (previous.clone(), BTreeSet::new())
    } else {
        terminal::previous_view(previous, &s)?
    };
    let mut peers = current.clone();
    for guard in terminal_guards {
        let row = peers
            .get(&guard)
            .context("completed209 terminal predecessor guard omitted")?;
        idle(row)?;
        peers.remove(&guard);
    }
    for name in [&c.unit, &s.guard_units[s.phase.name()]] {
        peers
            .remove(name)
            .context("completed209 new owner/guard omitted from census")?;
        if let Some(old) = previous["unit_census"].get(name) {
            idle(old)?;
            peers.insert(name.clone(), old.clone());
        }
    }
    maintenance_capacity::current_owners(&previous_view, &peers)?;
    owner_shape(
        &l,
        current.get(&c.unit).context("completed209 child missing")?,
    )?;
    live(&c, &l)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Spec, Value, Value, String) {
        let (s, a, mut l, helper) = launch::tests::fixture();
        l["child_execution_authorized"] = json!(false);
        l["publication_authorized"] = json!(false);
        l["remote_mutations"] = json!(false);
        l["r2_mutations"] = json!(false);
        let argv = barrier::launcher_argv(&s);
        let command = format!(
            "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            s.programs["launcher"].artifact.path.display(),
            argv.join(" ")
        );
        l["effective_unit"] = json!({"ExecStart":command});
        l["owner"]["ExecStart"] = l["effective_unit"]["ExecStart"].clone();
        (s, a, l, helper)
    }
    #[test]
    fn g209_event_accepts_real_generic_capture_shape_not_legacy_or_waiter() {
        let (s, a, l, helper) = fixture();
        capture_shape(&l).unwrap();
        launch::saved_shape(&l, &s, Phase::Full, &helper, &a).unwrap();
        let b = BoundFile {
            path: "/sealed/launch.json".into(),
            sha256: "a".repeat(64),
        };
        let c = claim(&b, &l).unwrap();
        assert_eq!(c.phase, "full-verification");
        assert_eq!(c.evidence, vec![b]);
        for (key, value) in [
            (
                "schema",
                json!("jetstreamer-private-epoch209-singleton-launch-v1"),
            ),
            ("schema", json!(barrier::RELEASE)),
            ("epoch", json!(210)),
            ("phase", json!("plugin")),
            ("unit", json!(singleton209::UNIT)),
            ("child_execution_authorized", json!(true)),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = l.clone();
            bad[key] = value;
            assert!(capture_shape(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn g209_event_rejects_changed_release_source_floor_and_cap_proofs() {
        let (s, a, l, helper) = fixture();
        for (pointer, value) in [
            ("/process/source_read_only_mount", json!(false)),
            ("/process/executable_sha256", json!("0".repeat(64))),
            ("/process/native_limits/memory.max", json!("max")),
            ("/guard_plan_contents/minimum_free_bytes", json!(101)),
            (
                "/startup_release_contents/startup_plan_contents/archive_directory",
                json!("/foreign"),
            ),
            (
                "/startup_release_contents/phase_spec_contents/epoch",
                json!(210),
            ),
        ] {
            let mut bad = l.clone();
            *bad.pointer_mut(pointer)
                .expect("real captured control field") = value;
            assert!(
                launch::saved_shape(&bad, &s, Phase::Full, &helper, &a).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn g209_event_rejects_replaced_native_owner_and_command() {
        let (_, _, l, _) = fixture();
        owner_shape(&l, &l["owner"]).unwrap();
        native_shape(&l, &l["process"]).unwrap();
        for key in ["InvocationID", "MainPID", "ControlGroup", "ExecStart"] {
            let mut u = l["owner"].clone();
            u[key] = json!("foreign");
            assert!(owner_shape(&l, &u).is_err(), "{key}");
        }
        for (pointer, value) in [
            ("/start_ticks", json!(999)),
            ("/native_limits/memory.max", json!("max")),
            ("/source_read_only_mount", json!(false)),
            ("/executable_sha256", json!("0".repeat(64))),
        ] {
            let mut p = l["process"].clone();
            *p.pointer_mut(pointer).unwrap() = value;
            assert!(native_shape(&l, &p).is_err(), "{pointer}");
        }
    }
    #[test]
    fn g209_event_clock_rejects_stale_backwards_and_future_capture() {
        let (_, _, l, _) = fixture();
        let o = json!({"recorded_at_utc":"1970-01-01T00:15:00Z"});
        let prev = json!({"recorded_unix_seconds":910});
        assert_eq!(event_clock(&prev, &o, &l, 921).unwrap(), 920);
        assert!(event_clock(&json!({"recorded_unix_seconds":920}), &o, &l, 921).is_err());
        assert!(event_clock(&prev, &o, &l, 919).is_err());
        assert!(event_clock(&prev, &o, &l, 1221).is_err());
        let mut bad = l.clone();
        bad["captured_unix_seconds"] = json!(900);
        assert!(event_clock(&prev, &o, &bad, 921).is_err());
        let mut bad = l;
        bad["process"]["native_start_clock"]["started_unix_seconds"] = json!(921);
        assert!(event_clock(&prev, &o, &bad, 921).is_err());
    }
    #[test]
    fn g209_event_plan_delta_preserves_all_gates_peers_and_history() {
        let (s, _, l, _) = fixture();
        let c = claim(
            &BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "a".repeat(64),
            },
            &l,
        )
        .unwrap();
        let old = json!({"tracked_units":["peer.service"],"pipeline_claims":[],
            "gates":{"209":{"state":"blocked-qualification","evidence":["original"]}},
            "capped204205_history":[{"failure":"preserved"}],"observer":{"sha256":"a".repeat(64)}});
        let mut new = old.clone();
        new["pipeline_claims"] = json!([c]);
        new["gates"]["209"] = pipeline_gate(&old["gates"]["209"], &c).unwrap();
        new["tracked_units"] = json!(["peer.service", c.unit, s.guard_units["full"]]);
        plan_delta(&old, &new, &c, &s.guard_units["full"], None).unwrap();
        for (pointer, value) in [
            ("/gates/209/state", json!("remote-ready")),
            ("/capped204205_history", json!([])),
            ("/observer/sha256", json!("b".repeat(64))),
            ("/tracked_units", json!([c.unit, s.guard_units["full"]])),
        ] {
            let mut bad = new.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                plan_delta(&old, &bad, &c, &s.guard_units["full"], None).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn g209_late_event_changes_only_the_explicit_fresh_observer_and_new_owner() {
        let (s, _, l, _) = fixture();
        let c = claim(
            &BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "a".repeat(64),
            },
            &l,
        )
        .unwrap();
        let old = json!({"tracked_units":["peer.service"],"pipeline_claims":[],
            "gates":{"209":{"state":"blocked-qualification","evidence":["original"]}},
            "observer":{"path":"/sealed/old.json","sha256":"a".repeat(64)},
            "protected_peer":{"invocation_id":"b".repeat(32)}});
        let observer = BoundFile {
            path: "/sealed/fresh.json".into(),
            sha256: "c".repeat(64),
        };
        let mut new = old.clone();
        new["observer"] = private157::binding(&observer);
        new["pipeline_claims"] = json!([c]);
        new["tracked_units"] = json!(["peer.service", c.unit, s.guard_units["full"]]);
        new["gates"]["209"] = pipeline_gate(&old["gates"]["209"], &c).unwrap();
        assert!(plan_delta(&old, &new, &c, &s.guard_units["full"], None).is_err());
        plan_delta(&old, &new, &c, &s.guard_units["full"], Some(&observer)).unwrap();
        for (pointer, value) in [
            ("/observer/sha256", json!("0".repeat(64))),
            ("/protected_peer/invocation_id", json!("0".repeat(32))),
            ("/gates/209/state", json!("remote-ready")),
        ] {
            let mut bad = new.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                plan_delta(&old, &bad, &c, &s.guard_units["full"], Some(&observer)).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn g209_late_event_keeps_old_native_start_but_requires_fresh_observer_and_capture() {
        let (_, _, mut l, _) = fixture();
        l["captured_unix_seconds"] = json!(10000);
        let previous = json!({"recorded_unix_seconds":910});
        let old = json!({"recorded_at_utc":"1970-01-01T00:15:00Z"});
        assert!(event_clock(&previous, &old, &l, 10001).is_err());
        let fresh = json!({"recorded_at_utc":"1970-01-01T02:45:00Z"});
        assert_eq!(event_clock(&previous, &fresh, &l, 10001).unwrap(), 10000);
        assert!(event_clock(&previous, &fresh, &l, 10301).is_err());
    }
    #[test]
    fn g209_event_request_cannot_import_skip_flags_or_authority() {
        let b = json!({"path":"/sealed/file","sha256":"a".repeat(64)});
        let mut r = json!({"schema":REQUEST,"observer":b,"previous_fleet":b,"launch":b,
            "output_directory":"/var/lib/jetstreamer/horizon-generic209-full-event-test"});
        assert!(serde_json::from_value::<Request>(r.clone()).is_ok());
        for key in [
            "ignore_peer",
            "resource_samples_taken",
            "skip_capture",
            "replay_launch_authorized",
        ] {
            r[key] = json!(true);
            assert!(serde_json::from_value::<Request>(r.clone()).is_err());
            r.as_object_mut().unwrap().remove(key);
        }
        for key in [
            "replay_launch_authorized",
            "publication_authorized",
            "capacity_credit_authorized",
            "r2_mutations",
        ] {
            assert_eq!(denied()[key], false);
        }
    }
    #[test]
    fn completed209_delivery_claims_use_real_plugin_and_upload_phases_and_reject_terminal_as_live()
    {
        let (_, _, base, _) = fixture();
        for (p, wire) in [
            (Phase::Plugin, "plugin-verification"),
            (Phase::Upload, "upload-readback"),
        ] {
            let mut l = base.clone();
            l["phase"] = json!(p);
            l["phase_spec_contents"] =
                json!({"launcher_transition":{"authenticated_by_checked_launch":true}});
            let unit = format!("horizon-qualify-209-generic-{}-v12.service", p.name());
            l["unit"] = json!(unit);
            l["owner"]["Id"] = json!(unit);
            capture_shape(&l).unwrap();
            let c = claim(
                &BoundFile {
                    path: "/sealed/live.json".into(),
                    sha256: "a".repeat(64),
                },
                &l,
            )
            .unwrap();
            assert_eq!(c.phase, wire);
            l["schema"] = json!(terminal::SCHEMA);
            assert!(capture_shape(&l).is_err());
        }
        assert!(is_event(&json!({"schema":DELIVERY_EVENT})));
    }
    #[test]
    fn completed209_event_uses_actual_admission_capacity_resource_basis_without_fabricating_top_level_field()
     {
        let (mut s, _, _, _) = fixture();
        s.resource_basis = json!({"fleet":{"path":"/sealed/fleet.json","sha256":"a".repeat(64)},
            "observer":{"path":"/sealed/observer.json","sha256":"b".repeat(64)}});
        let mut admission = json!({"capacity":{"resource_basis":s.resource_basis}});
        assert!(admission.get("resource_basis").is_none());
        admitted_resource(&admission, &s).unwrap();
        admission["resource_basis"] = s.resource_basis.clone();
        admission["capacity"]["resource_basis"]["fleet"]["sha256"] = json!("0".repeat(64));
        assert!(admitted_resource(&admission, &s).is_err());
    }
}
