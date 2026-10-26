//! A captured Full/plugin/upload207 child may join one accepted resource sample. This is
//! metadata ownership, never replay, archive readiness, or capacity credit.
use super::*;
mod status;
pub(in crate::fleet) use status::{publish, status_matches};
pub(in crate::fleet) const EVENT_SCHEMA: &str = "jetstreamer-completed207-phase-captured-event-v1";
const REQUEST: &str = "jetstreamer-completed207-phase-event-request-v1";
const MAX_EVENT_AGE: u64 = 300;

fn wire(l: &Value) -> Result<&'static str> {
    match l["phase"].as_str() {
        Some("full") => Ok("full-verification"),
        Some("plugin") => Ok("plugin-verification"),
        Some("upload") => Ok("upload-readback"),
        _ => bail!("207 event is not a captured delivery phase"),
    }
}
fn status_phase(l: &Value) -> Result<&'static str> {
    Ok(if wire(l)? == "upload-readback" {
        "upload"
    } else {
        "verification"
    })
}

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
fn current_peers(
    f: &Value,
    current: &BTreeMap<String, Value>,
    handoff: Option<&BoundFile>,
) -> Result<()> {
    if let Some(binding) = handoff {
        let p = terminal225_peer::Profile::load(binding, f)?;
        return maintenance_capacity::current_owners(
            &p.without(f)?,
            &p.without_current(f, current)?,
        );
    }
    maintenance_capacity::current_owners(f, current)
}
fn capture_shape(l: &Value) -> Result<()> {
    ensure!(
        l["schema"] == "jetstreamer-completed-archive-phase-launch-v1"
            && l["epoch"] == 207
            && wire(l).is_ok()
            && l["child_execution_authorized"] == false
            && l["publication_authorized"] == false
            && l["remote_mutations"] == false
            && l["r2_mutations"] == false
            && pipeline_scope(wire(l)?, string(l, "unit")?) == Some(207)
            && l["owner"]["Id"] == l["unit"]
            && l["owner"]["InvocationID"] == l["invocation_id"]
            && l["owner"]["NRestarts"] == "0"
            && l["owner"]["ActiveState"] == "active"
            && l["owner"]["SubState"] == "running"
            && l["process"]["source_read_only_mount"] == true
            && l["startup_release"].is_object()
            && l["startup_release_contents"]["schema"] == barrier::RELEASE,
        "completed207 event requires a genuine captured delivery child, not a legacy launch or waiter"
    );
    Ok(())
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed207 event missing text: {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed207 event missing integer: {k}"))
}
fn claim(binding: &BoundFile, l: &Value) -> Result<PipelineClaim> {
    capture_shape(l)?;
    Ok(PipelineClaim {
        epoch: 207,
        phase: wire(l)?.into(),
        unit: string(l, "unit")?.into(),
        invocation_id: string(l, "invocation_id")?.into(),
        expected_exec_start: string(&l["effective_unit"], "ExecStart")?.into(),
        evidence: vec![binding.clone()],
    })
}
fn checked_launch(binding: &BoundFile) -> Result<(PipelineClaim, Value, Spec, Value)> {
    let l = read(binding)?;
    let c = claim(binding, &l)?;
    let (actual, saved, s, a) = peer::claim_launch(&c)?;
    ensure!(
        actual == *binding
            && saved == l
            && s.epoch == 207
            && matches!(&s.origin, Origin::Singleton207 { .. }),
        "completed207 capture differs from its qualified saved launch/control proofs"
    );
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
            "completed207 live child changed: {k}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            string(&l["owner"], "ExecStart")?,
            string(u, "ExecStart")?
        ),
        "completed207 live child command changed"
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
        "completed207 current archive mount is writable"
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
            "completed207 native child/control proof changed: {k}"
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
        "completed207 event is stale, backwards, or predates its actual native child"
    );
    Ok(captured)
}
fn accepted(previous: &Value, observer: &BoundFile, o: &Value) -> Result<()> {
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
                .context("completed207 prior roster missing")?
                .iter()
                .any(|r| r["epoch"] == 207),
        "completed207 event must retain the complete accepted observation and cannot replace an active207 owner"
    );
    Ok(())
}
fn event_launch(event: &Value) -> Result<(PipelineClaim, Value, Spec, Value)> {
    ensure!(
        event["schema"] == EVENT_SCHEMA
            && event["epoch"] == 207
            && matches!(
                event["phase"].as_str(),
                Some("full-verification" | "plugin-verification" | "upload-readback")
            )
            && event["authority"] == denied(),
        "completed207 event scope/authority differs"
    );
    let b: BoundFile = serde_json::from_value(event["launch"].clone())?;
    let result = checked_launch(&b)?;
    ensure!(
        event["claim"] == serde_json::to_value(&result.0)?
            && event["phase"] == result.0.phase
            && event["recorded_unix_seconds"] == result.1["captured_unix_seconds"]
            && utc_seconds(string(event, "sampled_at_utc")?)?
                == number(&result.1, "captured_unix_seconds")?,
        "completed207 event borrowed a different capture or clock"
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
                .is_some_and(|n| n.starts_with("horizon-generic207-phase-event-")),
        "completed207 event needs its dedicated private namespace"
    );
    Ok(())
}
fn private_output(path: &Path) -> Result<()> {
    output_scope(path)?;
    ensure!(
        fs::read_dir(path)?.next().is_none(),
        "completed207 event attempt is not empty"
    );
    Ok(())
}
pub(in crate::fleet) fn prepare() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
        "completed207 event preparation requires root"
    );
    let (binding, self_sha) = publication203::parsed_args("prepare-completed207-phase-event")?;
    let r: Request = serde_json::from_value(read(&binding)?)?;
    ensure!(
        r.schema == REQUEST,
        "completed207 event request schema differs"
    );
    private_output(&r.output_directory)?;
    let previous = read(&r.previous_fleet)?;
    let o = read(&r.observer)?;
    accepted(&previous, &r.observer, &o)?;
    let (c, l, s, a) = checked_launch(&r.launch)?;
    ensure!(
        a["resource_basis"]["observer"] == private157::binding(&r.observer)
            && a["resource_basis"]["fleet"] == private157::binding(&r.previous_fleet),
        "completed207 event substituted the child's admitted resource context"
    );
    let captured = event_clock(&previous, &o, &l, now()?)?;
    live(&c, &l)?;
    let event = json!({"schema":EVENT_SCHEMA,"epoch":207,"phase":c.phase,
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
        .context("completed207 prior plan object missing")?
        .entry("pipeline_claims")
        .or_insert_with(|| json!([]));
    let claims = plan["pipeline_claims"]
        .as_array_mut()
        .context("completed207 prior claim list missing")?;
    ensure!(
        !claims.iter().any(|v| v["unit"] == c.unit),
        "completed207 owner already registered"
    );
    claims.push(serde_json::to_value(&c)?);
    plan["gates"]["207"] = pipeline_gate(&plan["gates"]["207"], &c)?;
    let tracked = plan["tracked_units"]
        .as_array_mut()
        .context("completed207 tracked roster missing")?;
    for name in [&c.unit, &s.guard_units[s.phase.name()]] {
        if !tracked.iter().any(|n| n.as_str() == Some(name.as_str())) {
            tracked.push(json!(name));
        }
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
        .context("completed207 complete census missing")?
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
    accepted(previous, &p.observer, &o)?;
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
            && a["resource_basis"]["observer"] == event["observer"]
            && a["resource_basis"]["fleet"] == event["previous_fleet"]
            && number(event, "recorded_unix_seconds")? == t,
        "completed207 event lost its exact admitted predecessor/observation"
    );
    let request: Request =
        serde_json::from_value(read(&serde_json::from_value(event["request"].clone())?)?)?;
    ensure!(
        request.schema == REQUEST
            && event["observer"] == private157::binding(&request.observer)
            && event["previous_fleet"] == private157::binding(&request.previous_fleet)
            && event["launch"] == private157::binding(&request.launch)
            && event["output_directory"] == serde_json::to_value(&request.output_directory)?
            && p.metadata_event
                .as_ref()
                .is_some_and(|b| b.path == request.output_directory.join("event.json"))
            && pb.path == request.output_directory.join("fleet-plan.json")
            && p.output == request.output_directory.join("fleet.json"),
        "completed207 event request/output namespace changed"
    );
    output_scope(&request.output_directory)?;
    let old = read(&serde_json::from_value(
        json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}),
    )?)?;
    let new = read(pb)?;
    plan_delta(&old, &new, &c, &s.guard_units[s.phase.name()])?;
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
        "completed207 event changed claim history"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.insert(c.unit.clone());
    tracked.insert(s.guard_units[s.phase.name()].clone());
    ensure!(
        tracked == p.tracked_units.iter().cloned().collect(),
        "completed207 event changed unrelated tracked owners"
    );
    ensure!(
        p.metadata_event
            .as_ref()
            .is_some_and(|b| read(b).is_ok_and(|v| v == *event)),
        "completed207 event differs from the registered immutable event"
    );
    Ok(())
}
fn plan_delta(old: &Value, new: &Value, c: &PipelineClaim, guard: &str) -> Result<()> {
    let old_claims = old
        .get("pipeline_claims")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut expected = old_claims
        .as_array()
        .context("completed207 prior claims are not an array")?
        .clone();
    ensure!(
        !expected.iter().any(|v| v["unit"] == c.unit),
        "completed207 owner already in history"
    );
    expected.push(serde_json::to_value(c)?);
    ensure!(
        new["pipeline_claims"] == json!(expected),
        "completed207 pipeline history reordered or changed"
    );
    let mut tracked: BTreeSet<String> = serde_json::from_value(old["tracked_units"].clone())?;
    tracked.insert(c.unit.clone());
    tracked.insert(guard.into());
    let actual: Vec<String> = serde_json::from_value(new["tracked_units"].clone())?;
    ensure!(
        actual.len() == tracked.len() && actual.into_iter().collect::<BTreeSet<_>>() == tracked,
        "completed207 tracked census changed or duplicated"
    );
    let mut left = old.clone();
    let mut right = new.clone();
    let expected_gate = pipeline_gate(&old["gates"]["207"], c)?;
    ensure!(
        new["gates"]["207"] == expected_gate,
        "completed207 event changed qualification history or claimed archive readiness"
    );
    left["gates"]["207"] = expected_gate;
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
        "completed207 event changed unrelated policy, gates, history or ownership"
    );
    Ok(())
}
fn pipeline_gate(old: &Value, c: &PipelineClaim) -> Result<Value> {
    ensure!(
        matches!(
            old["state"].as_str(),
            Some("blocked-qualification" | "failed-needs-repair" | "post-replay-pipeline")
        ),
        "completed207 event cannot replace a ready or otherwise unqualified gate"
    );
    let mut gate = old.clone();
    // The generic pipeline validator requires this observational classification.
    // No archive, verifier, plugin, upload or sidecar gate is promoted by it.
    gate["state"] = json!("post-replay-pipeline");
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("completed207 prior gate evidence missing")?;
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
    let mut peers = current.clone();
    for name in [&c.unit, &s.guard_units[s.phase.name()]] {
        peers
            .remove(name)
            .context("completed207 new owner/guard omitted from census")?;
        if let Some(old) = previous["unit_census"].get(name) {
            idle(old)?;
            peers.insert(name.clone(), old.clone());
        }
    }
    let handoff = s
        .resource_basis
        .get("epoch225_handoff")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value::<BoundFile>(v.clone()))
        .transpose()?;
    current_peers(previous, &peers, handoff.as_ref())?;
    owner_shape(
        &l,
        current.get(&c.unit).context("completed207 child missing")?,
    )?;
    live(&c, &l)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn captured(phase: &str) -> Value {
        let name = format!("horizon-qualify-207-generic-{phase}-v1.service");
        json!({"schema":"jetstreamer-completed-archive-phase-launch-v1","epoch":207,"phase":phase,
            "unit":name,"invocation_id":"b".repeat(32),"child_execution_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "owner":{"Id":name,"InvocationID":"b".repeat(32),"NRestarts":"0","ActiveState":"active","SubState":"running"},
            "effective_unit":{"ExecStart":"captured exact command"},"process":{"source_read_only_mount":true},
            "startup_release":{"path":"/sealed/release.json","sha256":"a".repeat(64)},"startup_release_contents":{"schema":barrier::RELEASE}})
    }
    #[test]
    fn captured207_phases_never_promote_a_terminal_replay_or_a209_child() {
        let b = BoundFile {
            path: "/sealed/capture.json".into(),
            sha256: "a".repeat(64),
        };
        for (phase, wire_phase, status) in [
            ("full", "full-verification", "verification"),
            ("plugin", "plugin-verification", "verification"),
            ("upload", "upload-readback", "upload"),
        ] {
            let v = captured(phase);
            capture_shape(&v).unwrap();
            assert_eq!(claim(&b, &v).unwrap().phase, wire_phase);
            assert_eq!(status_phase(&v).unwrap(), status);
            for (key, bad) in [
                ("epoch", json!(209)),
                (
                    "unit",
                    json!(format!("horizon-qualify-209-generic-{phase}-v1.service")),
                ),
                ("phase", json!("replay")),
                ("schema", json!(singleton207::SCHEMA)),
                ("child_execution_authorized", json!(true)),
            ] {
                let mut changed = v.clone();
                changed[key] = bad;
                assert!(capture_shape(&changed).is_err(), "{key}");
            }
            let mut changed = v.clone();
            changed["owner"]["NRestarts"] = json!("1");
            assert!(capture_shape(&changed).is_err());
            changed = v;
            changed["process"]["source_read_only_mount"] = json!(false);
            assert!(capture_shape(&changed).is_err());
        }
    }
    #[test]
    fn phase_event_keeps_prior_stage_claims_native_evidence_and_other_epochs() {
        let b = BoundFile {
            path: "/sealed/new-stage.json".into(),
            sha256: "a".repeat(64),
        };
        let c = claim(&b, &captured("plugin")).unwrap();
        let guard = "horizon-generic207-plugin-protective-v1.service";
        let old = json!({"gates":{"207":{"state":"post-replay-pipeline","evidence":[{"path":"/sealed/native207.json","sha256":"c".repeat(64)}]},"209":{"state":"post-replay-pipeline","evidence":[]}},"pipeline_claims":[{"unit":"old-full207","unchanged":true}],"tracked_units":["old-full207"],"diagnostics":[{"epoch":233,"original":true}]});
        let mut new = old.clone();
        new["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .push(json!(c));
        new["tracked_units"] = json!(["old-full207", c.unit, guard]);
        new["gates"]["207"] = pipeline_gate(&old["gates"]["207"], &c).unwrap();
        plan_delta(&old, &new, &c, guard).unwrap();
        for pointer in [
            "/pipeline_claims/0",
            "/gates/207/evidence/0",
            "/gates/209/state",
            "/diagnostics/0",
        ] {
            let mut changed = new.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(plan_delta(&old, &changed, &c, guard).is_err(), "{pointer}");
        }
    }
}
