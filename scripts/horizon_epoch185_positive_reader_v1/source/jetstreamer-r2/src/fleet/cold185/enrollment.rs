//! Exact metadata enrollment of the genuine epoch 185 cold-prefix owner.
//! Registration is not launch, full replay, verification or publication authority.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::fleet) const FIELD: &str = "epoch185_cold_startpre_registration";
pub(in crate::fleet) const SCHEMA: &str = "horizon-epoch185-startpre-fleet-registration-v1";
const ENROLLMENT_ROOT: &str = super::ROOT;
const GUARD_MEMORY_BYTES: u64 = 256 << 20;
const RETAINED145_SUFFIX: [&str; 7] = [
    "horizon-qualify-145-cached-b2a09f57de39c384.service",
    "horizon-qualify-145-cached-b2a09f57de39c384-guard.service",
    "horizon-qualify-145-cached-b2a09f57de39c384-guard.timer",
    "horizon-qualify-145-cached-b2a09f57de39c384-stop.service",
    "horizon-extract145-prefix-shared72h-20261107-v8g1.service",
    "horizon-guard145-prefix-shared72h-20261107-v8g1.service",
    "horizon-guard145-prefix-shared72h-20261107-v8g1.timer",
];

fn enrolled_units(old: &Value, event: &Value) -> Result<Value> {
    let selected = horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::selected(old)?;
    let mut names = old["tracked_units"]
        .as_array()
        .context("cold185 old tracked units")?
        .clone();
    let at = if selected {
        ensure!(
            names.ends_with(&RETAINED145_SUFFIX.map(|name| json!(name)))
                && RETAINED145_SUFFIX.iter().all(|name| {
                    names
                        .iter()
                        .filter(|value| value.as_str() == Some(name))
                        .count()
                        == 1
                }),
            "cold185 enrollment requires exact retained cached/live145 suffix"
        );
        names.len() - RETAINED145_SUFFIX.len()
    } else {
        names.len()
    };
    let mut additions = Vec::new();
    for key in ["actor_unit", "guard_unit", "timer_unit"] {
        ensure!(
            !names.iter().any(|name| *name == event[key]),
            "cold185 fresh enrollment already exists in historical tracked units"
        );
        additions.push(event[key].clone());
    }
    names.splice(at..at, additions);
    Ok(json!(names))
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("cold185 enrollment missing {key}"))
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("cold185 enrollment missing integer {key}"))
}
fn checked_binding(value: &Value) -> Result<BoundFile> {
    let b: BoundFile = serde_json::from_value(value.clone())?;
    ensure!(
        b.path.is_absolute() && is_lower_hex(&b.sha256, 64),
        "cold185 enrollment binding is not absolute and digest-bound"
    );
    ensure!(
        value
            .as_object()
            .is_some_and(|o| o.len() == 2 && o.contains_key("path") && o.contains_key("sha256")),
        "cold185 enrollment binding has an undeclared field"
    );
    Ok(b)
}
fn epoch185_claim(event: &Value, registration: &Value) -> Result<Value> {
    checked_binding(registration)?;
    Ok(json!({"epoch":185,"unit":event["actor_unit"],
        "invocation_id":event["actor_invocation_id"],"scratch_path":event["run_root"],
        "launch_receipt":registration}))
}
fn event_shape(event: &Value, registration: &Value, now: u64) -> Result<()> {
    ensure!(
        event["schema"] == SCHEMA
            && event["epoch"] == 185
            && event["phase"] == "verification"
            && event["resource_credit_bytes"] == 0
            && event["ordinary_full_replay_authorized"] == false
            && event["publication_authorized"] == false
            && event["r2_mutations"] == false,
        "cold185 enrollment event grants authority or changes scope"
    );
    let iid = text(event, "actor_invocation_id")?;
    ensure!(
        is_lower_hex(iid, 32)
            && integer(event, "ready_pid")? > 1
            && integer(event, "ready_start_ticks")? > 0,
        "cold185 enrollment lacks genuine ready owner identity"
    );
    let at = integer(event, "sampled_at")?;
    let started = integer(event, "ready_started_at")?;
    let deadline = integer(event, "setup_deadline_at")?;
    ensure!(
        started <= at
            && at <= now
            && now < deadline
            && deadline > started
            && deadline - started <= 600,
        "cold185 enrollment crossed original admitted setup deadline or readiness"
    );
    let b = checked_binding(registration)?;
    ensure!(
        b.path
            == Path::new(ENROLLMENT_ROOT)
                .join(iid)
                .join("registration.json"),
        "cold185 enrollment receipt path crossed actual invocation"
    );
    for key in ["task", "previous_fleet", "observer"] {
        checked_binding(&event[key])?;
    }
    let mut names = BTreeSet::new();
    for key in ["actor_unit", "guard_unit", "timer_unit"] {
        let name = text(event, key)?;
        ensure!(
            names.insert(name) && !name.chars().any(char::is_whitespace),
            "cold185 enrollment actor/guard/timer aliases or ambiguous name"
        );
    }
    ensure!(
        text(event, "guard_unit")?.ends_with(".service")
            && text(event, "timer_unit")?.ends_with(".timer")
            && text(event, "actor_unit")?.ends_with(".service"),
        "cold185 enrollment unit kinds differ"
    );
    Ok(())
}

/// Pure complete policy check. The runtime caller authenticates every task,
/// source and native owner before calling this; this function grants no authority.
fn transition_shape(
    previous: &Value,
    old: &Value,
    plan: &Value,
    event: &Value,
    registration: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    event_shape(event, registration, now)?;
    ensure!(
        previous["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && old["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && old["first_epoch"] == 101
            && old["last_epoch"] == 200
            && old[FIELD].is_null()
            && old["observer"] == event["observer"]
            && previous["observer_receipt"] == event["observer"]["path"]
            && previous["observer_sha256"] == event["observer"]["sha256"]
            && previous["sampled_at_utc"] == sample
            && plan["observer"] == old["observer"]
            && plan["previous_fleet"] == event["previous_fleet"]
            && previous["plan"] == event["previous_plan"]["path"]
            && previous["plan_sha256"] == event["previous_plan"]["sha256"],
        "cold185 enrollment lost actual same-sample predecessor"
    );
    checked_binding(&event["previous_plan"])?;
    ensure!(
        plan[FIELD] == *registration && plan["metadata_event"] == *registration,
        "cold185 enrollment plan selectors do not name actual registration"
    );
    let mut expected = old.clone();
    for key in ["output", "previous_fleet", "metadata_event", FIELD] {
        expected[key] = plan[key].clone();
    }
    expected["tracked_units"] = enrolled_units(old, event)?;
    let claims = expected["diagnostics"]
        .as_array_mut()
        .context("cold185 old diagnostic claims")?;
    ensure!(
        !claims
            .iter()
            .any(|claim| claim["unit"] == event["actor_unit"]),
        "cold185 enrollment reuses an old actor unit"
    );
    for claim in claims.iter().filter(|claim| claim["epoch"] == 185) {
        inherited185_terminal(previous, claim, false)?;
    }
    for claim in old["pipeline_claims"]
        .as_array()
        .context("cold185 old pipelines")?
        .iter()
        .filter(|claim| claim["epoch"] == 185)
    {
        inherited185_terminal(previous, claim, true)?;
    }
    claims.push(epoch185_claim(event, registration)?);
    let gate = &mut expected["gates"]["185"];
    ensure!(
        matches!(
            gate["state"].as_str(),
            Some("failed-needs-repair" | "blocked-qualification")
        ),
        "cold185 enrollment cannot reopen a completed or ordinary claimed gate"
    );
    ensure!(
        plan["gates"]["185"]["state"] == gate["state"]
            && plan["gates"]["185"]["next_action"]
                .as_str()
                .is_some_and(|s| !s.trim().is_empty()),
        "cold185 private start-pre work cannot close repair or claim replay"
    );
    gate["next_action"] = plan["gates"]["185"]["next_action"].clone();
    gate["evidence"]
        .as_array_mut()
        .context("cold185 existing gate evidence")?
        .push(registration.clone());
    ensure!(
        expected == *plan,
        "cold185 enrollment changed unrelated history, policy, allocation or claims"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(name: &str) -> Value {
        json!({"path":format!("/test-only/{name}.json"),"sha256":"a".repeat(64)})
    }
    fn fixture() -> (Value, Value, Value, Value, Value, u64) {
        let iid = "1".repeat(32);
        let registration = json!({"path":format!("{ENROLLMENT_ROOT}/{iid}/registration.json"),"sha256":"b".repeat(64)});
        let gate = json!({"state":"failed-needs-repair","next_action":"retain original archive and repair","evidence":[binding("old-proof")],"reserve_stop":null});
        let old = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,
            "observer":binding("observer"),"output":"/test-only/old-fleet.json","previous_fleet":binding("older-fleet"),
            "metadata_event":binding("retained-private154-event"),"admission_transition_guard":null,
            "tracked_units":["old.service"],"diagnostics":[{"epoch":145,"unit":"old.service","invocation_id":"2".repeat(32),
            "scratch_path":"/test-only/old-root","launch_receipt":binding("old-launch")}],
            "pipeline_claims":[{"epoch":141,"unit":"old141.service","phase":"repair","evidence":[binding("old141")]}],
            "gates":{"185":gate,"199":{"state":"failed-needs-repair","next_action":"keep retained original controller","evidence":[binding("old199")]}},
            "epoch199_terminal_context":binding("retained-context"),"extra_historical_field":{"must_remain":true}});
        let previous = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "observer_receipt":old["observer"]["path"],"observer_sha256":old["observer"]["sha256"],
            "sampled_at_utc":"2026-11-05T18:28:09Z","plan":binding("old-plan")["path"],"plan_sha256":binding("old-plan")["sha256"]});
        let now = 1000;
        let event = json!({"schema":SCHEMA,"epoch":185,"phase":"verification","actor_unit":"horizon-qualify-185-capped-cold-test.service",
            "actor_invocation_id":iid,"guard_unit":"horizon-guard-185-capped-cold-test.service",
            "timer_unit":"horizon-guard-185-capped-cold-test.timer","ready_pid":4444,"ready_start_ticks":5555,
            "run_root":"/test-only/new185-root","ready_started_at":980,"sampled_at":990,"setup_deadline_at":1580,"task":binding("task"),
            "observer":old["observer"],"previous_fleet":binding("old-fleet"),"previous_plan":binding("old-plan"),
            "resource_credit_bytes":0,"ordinary_full_replay_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let mut next = old.clone();
        next["output"] = json!("/test-only/next-fleet.json");
        next["previous_fleet"] = event["previous_fleet"].clone();
        next[FIELD] = registration.clone();
        next["metadata_event"] = registration.clone();
        for key in ["actor_unit", "guard_unit", "timer_unit"] {
            next["tracked_units"]
                .as_array_mut()
                .unwrap()
                .push(event[key].clone());
        }
        next["diagnostics"]
            .as_array_mut()
            .unwrap()
            .push(epoch185_claim(&event, &registration).unwrap());
        next["gates"]["185"]["next_action"] =
            json!("actual start-pre cold prefix; suffix and all publication gates remain due");
        next["gates"]["185"]["evidence"]
            .as_array_mut()
            .unwrap()
            .push(registration.clone());
        (previous, old, next, event, registration, now)
    }
    #[test]
    #[ignore = "Root exact sealed failed21:30 plan, historical metadata only; no native admission"]
    fn actual2130_plan_composes_complete_transition_with_same_live145_consumer() {
        let binding = json!({"path":"/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-fleet-387a0dcd086f4f209e087059783107b8/spec.json",
            "sha256":"98124a339ae6f09cbe1036047e0fa4daeaced50e91c668d925f2dd511cd2f273"});
        let plan = bound_json(&checked_binding(&binding).unwrap()).unwrap();
        let registration = plan[FIELD].clone();
        let event = bound_json(&checked_binding(&registration).unwrap()).unwrap();
        let old = bound_json(&checked_binding(&event["previous_plan"]).unwrap()).unwrap();
        let previous = bound_json(&checked_binding(&event["previous_fleet"]).unwrap()).unwrap();
        assert_eq!(enrolled_units(&old, &event).unwrap(), plan["tracked_units"]);
        transition_shape(
            &previous,
            &old,
            &plan,
            &event,
            &registration,
            text(&previous, "sampled_at_utc").unwrap(),
            integer(&event, "sampled_at").unwrap(),
        )
        .unwrap();
        assert!(
            horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::selected(&plan)
                .unwrap()
        );
        let mut changed = plan.clone();
        changed["pipeline_claims"] = json!([]);
        assert!(transition_shape(
            &previous,
            &old,
            &changed,
            &event,
            &registration,
            text(&previous, "sampled_at_utc").unwrap(),
            integer(&event, "sampled_at").unwrap()
        )
        .is_err());
    }
    #[test]
    fn retained145_order_composes_with_exact_cold185_transition() {
        let (previous, mut old, mut plan, event, registration, now) = fixture();
        old["tracked_units"]
            .as_array_mut()
            .unwrap()
            .extend(RETAINED145_SUFFIX.map(|name| json!(name)));
        plan["tracked_units"] = enrolled_units(&old, &event).unwrap();
        transition_shape(
            &previous,
            &old,
            &plan,
            &event,
            &registration,
            "2026-11-05T18:28:09Z",
            now,
        )
        .unwrap();
        assert!(
            horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::selected(&plan)
                .unwrap()
        );
        for key in [
            "pipeline_claims",
            "epoch199_terminal_context",
            "extra_historical_field",
        ] {
            let mut changed = plan.clone();
            changed[key] = json!("foreign");
            assert!(transition_shape(
                &previous,
                &old,
                &changed,
                &event,
                &registration,
                "2026-11-05T18:28:09Z",
                now
            )
            .is_err());
        }
        let mut appended = plan.clone();
        let mut rows = old["tracked_units"].as_array().unwrap().clone();
        rows.extend([
            event["actor_unit"].clone(),
            event["guard_unit"].clone(),
            event["timer_unit"].clone(),
        ]);
        appended["tracked_units"] = json!(rows);
        assert!(transition_shape(
            &previous,
            &old,
            &appended,
            &event,
            &registration,
            "2026-11-05T18:28:09Z",
            now
        )
        .is_err());
    }
    #[test]
    fn malformed_retained145_suffix_never_reorders_or_drops_history() {
        let (_, mut old, _, event, _, _) = fixture();
        old["tracked_units"]
            .as_array_mut()
            .unwrap()
            .extend(RETAINED145_SUFFIX.map(|name| json!(name)));
        for mode in 0..3 {
            let mut changed = old.clone();
            let rows = changed["tracked_units"].as_array_mut().unwrap();
            match mode {
                0 => {
                    rows.remove(1);
                }
                1 => rows.swap(1, 2),
                _ => rows.insert(0, json!(RETAINED145_SUFFIX[0])),
            }
            let saved = changed.clone();
            assert!(enrolled_units(&changed, &event).is_err());
            assert_eq!(changed, saved);
        }
    }
    #[test]
    fn exact185_metadata_addition_preserves_complete_old_policy_and_failed_gate() {
        let (previous, old, plan, event, registration, now) = fixture();
        let original = old.clone();
        transition_shape(
            &previous,
            &old,
            &plan,
            &event,
            &registration,
            "2026-11-05T18:28:09Z",
            now,
        )
        .unwrap();
        assert_eq!(old, original);
        assert_eq!(plan["gates"]["185"]["state"], "failed-needs-repair");
        assert_eq!(plan["gates"]["199"], old["gates"]["199"]);
        assert_eq!(plan["pipeline_claims"], old["pipeline_claims"]);
        assert_eq!(
            plan["epoch199_terminal_context"],
            old["epoch199_terminal_context"]
        );
    }
    #[test]
    fn same_name_or_epoch_cannot_replace_an_inherited_claim() {
        let (previous, mut old, plan, event, registration, now) = fixture();
        old["diagnostics"]
            .as_array_mut()
            .unwrap()
            .push(epoch185_claim(&event, &registration).unwrap());
        assert!(transition_shape(
            &previous,
            &old,
            &plan,
            &event,
            &registration,
            "2026-11-05T18:28:09Z",
            now
        )
        .is_err());
        let (previous, old, mut plan, event, registration, now) = fixture();
        plan["diagnostics"][0]["invocation_id"] = json!("f".repeat(32));
        assert!(transition_shape(
            &previous,
            &old,
            &plan,
            &event,
            &registration,
            "2026-11-05T18:28:09Z",
            now
        )
        .is_err());
    }
    #[test]
    fn unrelated_gates_allocations_pipelines_and_fields_cannot_change() {
        let (previous, old, plan, event, registration, now) = fixture();
        for (pointer, value) in [
            ("/gates/199/state", json!("staged-admissible")),
            ("/pipeline_claims", json!([])),
            ("/epoch199_terminal_context", Value::Null),
            ("/extra_historical_field", json!({})),
            ("/observer", binding("different-observer")),
            ("/gates/185/state", json!("post-replay-pipeline")),
        ] {
            let mut broken = plan.clone();
            *broken.pointer_mut(pointer).unwrap() = value;
            assert!(
                transition_shape(
                    &previous,
                    &old,
                    &broken,
                    &event,
                    &registration,
                    "2026-11-05T18:28:09Z",
                    now
                )
                .is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn duplicate_extra_or_missing_actor_guard_and_timer_reject() {
        let (previous, old, plan, event, registration, now) = fixture();
        for mode in 0..4 {
            let mut broken = plan.clone();
            let names = broken["tracked_units"].as_array_mut().unwrap();
            match mode {
                0 => {
                    names.pop();
                }
                1 => names.push(event["guard_unit"].clone()),
                2 => names.push(json!("foreign.service")),
                _ => {
                    names.remove(0);
                }
            }
            assert!(
                transition_shape(
                    &previous,
                    &old,
                    &broken,
                    &event,
                    &registration,
                    "2026-11-05T18:28:09Z",
                    now
                )
                .is_err(),
                "mode{mode}"
            );
        }
    }
    #[test]
    fn stale_crossed_ready_identity_or_authority_cannot_enroll() {
        let (previous, old, plan, event, registration, now) = fixture();
        for (key, value) in [
            ("setup_deadline_at", json!(now)),
            ("ready_pid", json!(0)),
            ("actor_invocation_id", json!("f".repeat(32))),
            ("ready_started_at", json!(now + 1)),
            ("phase", json!("replay")),
            ("ordinary_full_replay_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("r2_mutations", json!(true)),
            ("resource_credit_bytes", json!(1)),
        ] {
            let mut broken = event.clone();
            broken[key] = value;
            assert!(
                transition_shape(
                    &previous,
                    &old,
                    &plan,
                    &broken,
                    &registration,
                    "2026-11-05T18:28:09Z",
                    now
                )
                .is_err(),
                "{key}"
            );
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationSpec {
    schema: String,
    task: BoundFile,
    previous_fleet: BoundFile,
    numeric_delivery_eta_millis: u64,
    output: PathBuf,
}
struct Loaded {
    binding: BoundFile,
    event: Value,
    proof: Value,
    previous_fleet: Value,
    previous_plan: Value,
}
fn sources(event: &Value, registration: &BoundFile, proof: &Value) -> Result<Vec<Value>> {
    let mut by_key = BTreeMap::new();
    for b in std::iter::once(json!(registration))
        .chain([
            event["task"].clone(),
            event["previous_fleet"].clone(),
            event["previous_plan"].clone(),
        ])
        .chain(
            proof["source_bindings"]
                .as_object()
                .context("cold185 complete source-binding map")?
                .values()
                .cloned(),
        )
    {
        let parsed = checked_binding(&b)?;
        by_key.insert((parsed.path, parsed.sha256), b);
    }
    ensure!(by_key.len() <= 64, "cold185 source census exceeds bound");
    Ok(by_key.into_values().collect())
}
fn native_map(proof: &Value) -> Result<&serde_json::Map<String, Value>> {
    let n = proof["native"]
        .as_object()
        .context("cold185 genuine full native census")?;
    ensure!(
        n.len() == 3
            && ["actor_unit", "guard_unit", "timer_unit"]
                .iter()
                .all(|key| proof[*key]
                    .as_str()
                    .is_some_and(|name| n.contains_key(name))),
        "cold185 native family dropped, added or aliased a role"
    );
    Ok(n)
}
fn original_fields_match(event: &Value, proof: &Value) -> Result<()> {
    for key in [
        "actor_unit",
        "actor_invocation_id",
        "guard_unit",
        "timer_unit",
        "run_root",
    ] {
        ensure!(
            event[key] == proof[key],
            "cold185 task crossed registered owner or path: {key}"
        );
    }
    ensure!(
        event["ready_pid"] == proof["ready"]["pid"]
            && event["ready_start_ticks"] == proof["ready"]["start_ticks"]
            && event["ready_started_at"] == proof["ready"]["started_at"]
            && event["admission_sha256"] == proof["admission"]["sha256"]
            && event["observer"] == proof["observer"]
            && event["limits"] == proof["limits"]
            && event["candidate_DATA_bytes"] == proof["candidate_DATA_bytes"]
            && event["guard_floor_bytes"] == proof["minimum_free_bytes"]
            && event["setup_deadline_at"] == proof["setup_deadline_at"],
        "cold185 original readiness, admission or resource promises changed"
    );
    native_map(proof)?;
    Ok(())
}
fn load_registration(binding: &BoundFile, now: u64) -> Result<Loaded> {
    let event = super::native::read_json(binding, 4 << 20)?;
    // Registration preserves its original clock. Fresh native proof below owns
    // the current stage; retaining the record does not reset setup deadlines.
    event_shape(&event, &json!(binding), integer(&event, "sampled_at")?)?;
    let task = checked_binding(&event["task"])?;
    let mut proof = super::load(&task, now)?;
    proof["registration"] = json!(binding);
    original_fields_match(&event, &proof)?;
    let previous_fleet = bound_json(&checked_binding(&event["previous_fleet"])?)?;
    let previous_plan = bound_json(&checked_binding(&event["previous_plan"])?)?;
    ensure!(
        previous_fleet["plan"] == event["previous_plan"]["path"]
            && previous_fleet["plan_sha256"] == event["previous_plan"]["sha256"]
            && previous_plan["observer"] == event["observer"],
        "cold185 registration previous complete fleet/plan binding crossed"
    );
    Ok(Loaded {
        binding: binding.clone(),
        event,
        proof,
        previous_fleet,
        previous_plan,
    })
}
fn selected(plan: &Value) -> Result<Option<BoundFile>> {
    if plan[FIELD].is_null() {
        return Ok(None);
    }
    Ok(Some(checked_binding(&plan[FIELD])?))
}
#[cfg(test)]
fn allocation_rows(loaded: &Loaded) -> Result<Value> {
    allocation_rows_selected(loaded, None)
}
fn allocation_rows_selected(loaded: &Loaded, plan: Option<&Value>) -> Result<Value> {
    let event = &loaded.event;
    let proof = &loaded.proof;
    let native = native_map(proof)?;
    let actor = text(event, "actor_unit")?;
    let guard = text(event, "guard_unit")?;
    let actor_memory = integer(&proof["limits"], "memory")?;
    let data = integer(proof, "candidate_DATA_bytes")?;
    let floor = integer(proof, "minimum_free_bytes")?;
    ensure!(
        actor_memory > 0
            && data > 0
            && floor > 0
            && (proof["stage"] == "terminal"
                || (native[actor]["MemoryMax"].as_str()
                    == Some(actor_memory.to_string().as_str())
                    && native[guard]["MemoryMax"].as_str()
                        == Some(GUARD_MEMORY_BYTES.to_string().as_str()))),
        "cold185 actor or independently charged guard limits changed"
    );
    let mut bindings = sources(event, &loaded.binding, proof)?;
    let pending = proof["stage"] == "start-pre";
    let lifecycle = if pending {
        ensure!(
            proof["guard_pending"] == true,
            "cold185 pending stage lost guard promise"
        );
        let guard_native = &native[guard];
        let timer_native = &native[text(event, "timer_unit")?];
        ensure!(
            guard_native["ActiveState"] == "inactive"
                && guard_native["MainPID"] == "0"
                && guard_native["ControlPID"] == "0"
                && guard_native["Job"] == ""
                && guard_native["InvocationID"] == ""
                && timer_native["ActiveState"] == "inactive"
                && timer_native["Job"] == ""
                && timer_native["InvocationID"] == "",
            "cold185 pending guard/timer is live, queued or has prior invocation"
        );
        None
    } else {
        ensure!(
            proof["guard_pending"] == false,
            "cold185 running/terminal lost genuine guard stage"
        );
        Some(super::lifecycle::load(
            plan.context("cold185 retained allocation requires explicit lifecycle selectors")?,
            event,
            proof,
        )?)
    };
    if let Some(plan) = plan.filter(|_| !pending) {
        for key in [super::lifecycle::FIELD, super::lifecycle::TERMINAL_FIELD] {
            if !plan[key].is_null() {
                checked_binding(&plan[key])?;
                bindings.push(plan[key].clone());
            }
        }
        bindings.sort_by_key(|b| {
            (
                b["path"].as_str().unwrap_or("").to_owned(),
                b["sha256"].as_str().unwrap_or("").to_owned(),
            )
        });
        bindings.dedup();
    }
    let total = actor_memory
        .checked_add(GUARD_MEMORY_BYTES)
        .context("cold185 pending guard memory overflow")?;
    let peers = vec![
        json!({"unit":actor,"invocation_id":event["actor_invocation_id"],
        "memory_max_bytes":total,"actual_actor_memory_hard_limit_bytes":actor_memory,
        "reserved_guard_memory_bytes":GUARD_MEMORY_BYTES,"guard_pending":pending,
        "guard_unit":guard,"timer_unit":event["timer_unit"],
        "data_reservation_bytes":data,"native_pool_suballocation":false,
        "cold185_registration":loaded.binding,"epoch185_task":event["task"],
        "source_bindings":bindings,"guard_floor_bytes":floor,"first_epoch":185,"last_epoch":185,
        "role":if pending { "cold185-capped-prefix-start-pre" }else{ "cold185-capped-prefix-retained" },
        "cold185_lifecycle":plan.map(|p|p[super::lifecycle::FIELD].clone()).unwrap_or(Value::Null),
        "cold185_terminal_retention":plan.map(|p|p[super::lifecycle::TERMINAL_FIELD].clone()).unwrap_or(Value::Null),
        "memory_or_DATA_credit_bytes":0}),
    ];
    let mut aggregate = json!({"peers":peers,"candidate_DATA_bytes":data,"guard_floor_bytes":floor,
        "source_bindings":bindings,"native":proof["native"],"registration":loaded.binding,
        "task":event["task"],"stage":proof["stage"],"guard_pending":pending,
        "prior_fleet":event["previous_fleet"],"prior_fleet_plan":event["previous_plan"],
        "prior_fleet_value":loaded.previous_fleet,"prior_fleet_plan_value":loaded.previous_plan,
        "registration_value":event,"resource_credit_bytes":0,"publication_authorized":false});
    if let Some(lifecycle) = lifecycle {
        let plan = plan.context("cold185 retained plan")?;
        aggregate["lifecycle"] = plan[super::lifecycle::FIELD].clone();
        aggregate["lifecycle_value"] = lifecycle;
        aggregate["terminal_retention"] = plan[super::lifecycle::TERMINAL_FIELD].clone();
        aggregate["terminal_context"] = proof["terminal_context"].clone();
        if proof["stage"] == "running" {
            aggregate["guard_history"] = proof["guard_history"].clone();
        }
    }
    Ok(aggregate)
}

pub(in crate::fleet) fn current_allocation(plan: &Value, now: u64) -> Result<Option<Value>> {
    let Some(binding) = selected(plan)? else {
        return Ok(None);
    };
    let loaded = load_registration(&binding, now)?;
    let expected = epoch185_claim(&loaded.event, &json!(binding))?;
    let claims = plan["diagnostics"]
        .as_array()
        .context("cold185 full diagnostic declaration")?;
    ensure!(
        claims
            .iter()
            .filter(|claim| claim["unit"] == loaded.event["actor_unit"])
            .count()
            == 1
            && claims.contains(&expected),
        "cold185 allocation requires the exact sole full diagnostic claim"
    );
    ensure!(
        plan["tracked_units"].as_array().is_some_and(|rows| [
            "actor_unit",
            "guard_unit",
            "timer_unit"
        ]
        .iter()
        .all(|key| rows
            .iter()
            .filter(|row| **row == loaded.event[*key])
            .count()
            == 1)),
        "cold185 allocation omitted or duplicated a genuine family owner"
    );
    Ok(Some(allocation_rows_selected(&loaded, Some(plan))?))
}
pub(in crate::fleet) fn validate_peer(peer: &Value) -> Result<()> {
    let binding = checked_binding(&peer["cold185_registration"])?;
    let loaded = load_registration(&binding, super::now()?)?;
    let selected = json!({"epoch185_cold_lifecycle":peer["cold185_lifecycle"],"epoch185_cold_terminal_retention":peer["cold185_terminal_retention"]});
    let allocation = allocation_rows_selected(&loaded, Some(&selected))?;
    ensure!(
        allocation["peers"]
            .as_array()
            .context("cold185 peer census")?
            .iter()
            .filter(|row| *row == peer)
            .count()
            == 1,
        "cold185 peer was changed, duplicated or granted resource credit"
    );
    Ok(())
}
pub(in crate::fleet) fn allocation(
    plan: &Value,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Option<Value>> {
    let value = current_allocation(plan, now)?;
    if let Some(value) = &value {
        let native = value["native"]
            .as_object()
            .context("cold185 fleet native proof")?;
        for (name, expected) in native {
            ensure!(
                census.get(name) == Some(expected),
                "cold185 fleet census differs from genuine current task native role: {name}"
            );
        }
    }
    Ok(value)
}

pub(in crate::fleet) fn validate_reader_bridge(
    plan: &Value,
    fleet: &Value,
    aggregate: &Value,
    clock: u64,
) -> Result<()> {
    let registration = checked_binding(&aggregate["registration"])?;
    let loaded = load_registration(&registration, clock)?;
    ensure!(
        {
            crate::fleet::epoch186::accounting::cold185_rollover::compare_allocations(
                aggregate,
                &allocation_rows_selected(&loaded, Some(plan))?,
            )?;
            true
        },
        "cold185 reader bridge substituted task/allocation evidence"
    );
    let event = &loaded.event;
    if loaded.proof["stage"] != "start-pre" {
        return validate_retained_reader_bridge(plan, fleet, aggregate, &loaded, clock);
    }
    let sample = text(&loaded.previous_fleet, "sampled_at_utc")?;
    transition_shape(
        &loaded.previous_fleet,
        &loaded.previous_plan,
        plan,
        event,
        &json!(registration),
        sample,
        clock,
    )?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet[FIELD] == json!(registration)
            && fleet["previous_fleet"] == event["previous_fleet"]
            && fleet["metadata_event"] == json!(registration)
            && fleet["observer_receipt"] == event["observer"]["path"]
            && fleet["observer_sha256"] == event["observer"]["sha256"]
            && fleet["sampled_at_utc"] == sample
            && fleet["producer_mutations"] == false
            && fleet["remote_mutations"] == false
            && fleet["publication_authorized"] == false
            && fleet["resource_admission_authorized"] == false,
        "cold185 reader bridge changed actual fleet lineage or grants authority"
    );
    validate_fleet_history(fleet, &loaded.previous_fleet, event, &json!(registration))?;
    let current_plan =
        checked_binding(&json!({"path":fleet["plan"],"sha256":fleet["plan_sha256"]}))?;
    ensure!(
        bound_json(&current_plan)? == *plan,
        "cold185 current full fleet/plan binding crossed"
    );
    let census: BTreeMap<String, Value> = serde_json::from_value(fleet["unit_census"].clone())?;
    let actual =
        allocation(plan, &census, clock)?.context("cold185 current fleet omitted allocation")?;
    ensure!(
        actual == *aggregate,
        "cold185 actual fleet allocation changed during bridge validation"
    );
    ensure!(
        fleet["cold185_allocation"] == *aggregate,
        "cold185 actual full fleet did not retain its exact typed allocation"
    );
    Ok(())
}

pub(in crate::fleet) struct FleetRoute {
    pub inherited: Plan,
    pub inherited_bound: BoundFile,
    aggregate: Value,
    event: Value,
    retained: bool,
}
impl FleetRoute {
    pub(in crate::fleet) fn claim_matches(&self, claim: &DiagnosticClaim) -> bool {
        claim.epoch == 185
            && claim.unit == self.event["actor_unit"]
            && claim.invocation_id == self.event["actor_invocation_id"]
            && claim.scratch_path.to_str() == self.event["run_root"].as_str()
            && json!(claim.launch_receipt) == self.aggregate["registration"]
    }
    pub(in crate::fleet) fn inherited_native(
        &self,
        actual: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        inherited_native_view(actual, &self.event, &self.aggregate["prior_fleet_value"])
    }
    pub(in crate::fleet) fn validate_current(
        &self,
        plan: &Value,
        census: &BTreeMap<String, Value>,
        now: u64,
    ) -> Result<Value> {
        let allocation =
            allocation(plan, census, now)?.context("cold185 selected route lost allocation")?;
        ensure!(
            {
                crate::fleet::epoch186::accounting::cold185_rollover::compare_allocations(
                    &self.aggregate,
                    &allocation,
                )?;
                true
            },
            "cold185 task or pending resource promise changed within fleet reconciliation"
        );
        Ok(allocation)
    }
}
pub(in crate::fleet) fn prepare(
    plan: &Value,
    sample: &str,
    now: u64,
    plan_bound: &BoundFile,
) -> Result<Option<FleetRoute>> {
    let Some(registration) = selected(plan)? else {
        return Ok(None);
    };
    let loaded = load_registration(&registration, now)?;
    if loaded.proof["stage"] != "start-pre" {
        let aggregate = current_allocation(plan, now)?.context("cold185 retained declaration")?;
        let inherited = super::lifecycle::project_plan(plan, &loaded.event, &loaded.previous_plan)?;
        return Ok(Some(FleetRoute {
            inherited: serde_json::from_value(inherited)?,
            inherited_bound: plan_bound.clone(),
            aggregate,
            event: loaded.event,
            retained: true,
        }));
    }
    ensure!(
        loaded.proof["stage"] == "start-pre" && loaded.proof["guard_pending"] == true,
        "cold185 enrollment route requires actual gated start-pre with pending protection"
    );
    transition_shape(
        &loaded.previous_fleet,
        &loaded.previous_plan,
        plan,
        &loaded.event,
        &json!(registration),
        sample,
        now,
    )?;
    let aggregate =
        current_allocation(plan, now)?.context("cold185 selected route lost exact declaration")?;
    Ok(Some(FleetRoute {
        inherited: serde_json::from_value(loaded.previous_plan)?,
        inherited_bound: checked_binding(&loaded.event["previous_plan"])?,
        aggregate,
        event: loaded.event,
        retained: false,
    }))
}
pub(in crate::fleet) fn validate_transition(
    previous: &Value,
    plan: &Value,
    event: &Value,
    sample: &str,
    now: u64,
) -> Result<()> {
    if super::lifecycle::selected(plan) {
        let registration =
            selected(plan)?.context("cold185 retained selector lost original registration")?;
        let loaded = load_registration(&registration, now)?;
        super::lifecycle::load(plan, &loaded.event, &loaded.proof)?;
        let is_metadata = previous[super::lifecycle::FIELD] != plan[super::lifecycle::FIELD]
            || previous[super::lifecycle::TERMINAL_FIELD] != plan[super::lifecycle::TERMINAL_FIELD];
        if is_metadata {
            return super::lifecycle::validate_transition(previous, plan, sample, event);
        }
        let observer = bound_json(&checked_binding(&plan["observer"])?)?;
        return super::lifecycle::validate_normal(previous, plan, &observer, sample);
    }
    let registration = selected(plan)?.context("cold185 metadata event lacks typed selector")?;
    let loaded = load_registration(&registration, now)?;
    ensure!(
        loaded.event == *event && loaded.previous_fleet == *previous,
        "cold185 metadata event or genuine previous fleet changed"
    );
    transition_shape(
        previous,
        &loaded.previous_plan,
        plan,
        event,
        &json!(registration),
        sample,
        now,
    )
}
pub(in crate::fleet) fn validate_launch(claim: &DiagnosticClaim, receipt: &Value) -> Result<()> {
    let loaded = load_registration(&claim.launch_receipt, super::now()?)?;
    ensure!(
        loaded.event == *receipt
            && epoch185_claim(receipt, &json!(claim.launch_receipt))?
                == json!({"epoch":claim.epoch,"unit":claim.unit,"invocation_id":claim.invocation_id,
            "scratch_path":claim.scratch_path,"launch_receipt":claim.launch_receipt}),
        "cold185 diagnostic claim differs from genuine task registration"
    );
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    let (spec_binding, self_sha) = super::parsed("enroll-cold185-startpre")?;
    let spec: RegistrationSpec =
        serde_json::from_value(super::native::read_json(&spec_binding, 4 << 20)?)?;
    ensure!(
        spec.schema == "horizon-epoch185-startpre-fleet-registration-spec-v1"
            && spec.numeric_delivery_eta_millis > 0,
        "cold185 registration spec or numeric delivery allowance missing"
    );
    let clock = super::now()?;
    let proof = super::load(&spec.task, clock)?;
    ensure!(
        proof["stage"] == "start-pre" && proof["guard_pending"] == true,
        "cold185 registration must originate in genuine gated start-pre"
    );
    ensure!(
        spec.numeric_delivery_eta_millis == authenticated_eta(&proof)?,
        "cold185 registration ETA differs from actual authenticated status"
    );
    let previous_fleet = bound_json(&spec.previous_fleet)?;
    let previous_plan = checked_binding(
        &json!({"path":previous_fleet["plan"],"sha256":previous_fleet["plan_sha256"]}),
    )?;
    let old = bound_json(&previous_plan)?;
    ensure!(
        old[FIELD].is_null()
            && old["observer"] == proof["observer"]
            && previous_fleet["observer_receipt"] == proof["observer"]["path"]
            && previous_fleet["observer_sha256"] == proof["observer"]["sha256"],
        "cold185 registration requires actual prelaunch same-resource fleet"
    );
    let iid = text(&proof, "actor_invocation_id")?;
    ensure!(
        spec.output == Path::new(ROOT).join(iid).join("registration.json"),
        "cold185 registration output not actual-IID namespace"
    );
    let event = json!({"schema":SCHEMA,"epoch":185,"phase":"verification","task":spec.task,
        "spec":spec_binding,"self_sha256":self_sha,
        "actor_unit":proof["actor_unit"],"actor_invocation_id":proof["actor_invocation_id"],
        "guard_unit":proof["guard_unit"],"timer_unit":proof["timer_unit"],"run_root":proof["run_root"],
        "ready_pid":proof["ready"]["pid"],"ready_start_ticks":proof["ready"]["start_ticks"],
        "ready_started_at":proof["ready"]["started_at"],"setup_deadline_at":proof["setup_deadline_at"],
        "sampled_at":clock,"sampled_at_utc":input161::utc(clock)?,
        "admission_sha256":proof["admission"]["sha256"],"observer":proof["observer"],
        "previous_fleet":spec.previous_fleet,"previous_plan":previous_plan,
        "limits":proof["limits"],"candidate_DATA_bytes":proof["candidate_DATA_bytes"],
        "guard_floor_bytes":proof["minimum_free_bytes"],"guard_pending":true,
        "numeric_delivery_eta_millis":spec.numeric_delivery_eta_millis,
        "resource_credit_bytes":0,"ordinary_full_replay_authorized":false,
        "publication_authorized":false,"r2_mutations":false});
    let mut raw = serde_json::to_vec_pretty(&event)?;
    raw.push(b'\n');
    let binding = json!({"path":spec.output,"sha256":hex_lower(&Sha256::digest(&raw))});
    event_shape(&event, &binding, clock)?;
    // Reopen the same original task immediately before no-clobber publication.
    let again = super::load(&spec.task, super::now()?)?;
    original_fields_match(&event, &again)?;
    ensure!(
        proof["native"] == again["native"],
        "cold185 native owners changed before registration commit"
    );
    super::persist(&spec.output, &event)?;
    println!(
        "{}",
        json!({"registration":binding,"epoch":185,"full_replay_or_publication_authorized":false})
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetAcceptanceSpec {
    schema: String,
    registration: BoundFile,
    actual_fleet: BoundFile,
    actual_fleet_plan: BoundFile,
    numeric_delivery_eta_millis: u64,
    output: PathBuf,
}
pub(crate) fn capture_fleet_acceptance() -> Result<()> {
    let (spec_binding, self_sha) = super::parsed("prove-cold185-fleet")?;
    let spec: FleetAcceptanceSpec =
        serde_json::from_value(super::native::read_json(&spec_binding, 4 << 20)?)?;
    ensure!(
        spec.schema == "horizon-epoch185-genuine-fleet-acceptance-spec-v1"
            && spec.numeric_delivery_eta_millis > 0,
        "cold185 genuine fleet acceptance spec"
    );
    let clock = super::now()?;
    let plan = bound_json(&spec.actual_fleet_plan)?;
    let fleet = bound_json(&spec.actual_fleet)?;
    ensure!(
        selected(&plan)?
            .as_ref()
            .is_some_and(|b| json!(b) == json!(spec.registration))
            && fleet["plan"] == spec.actual_fleet_plan.path.to_string_lossy().as_ref()
            && fleet["plan_sha256"] == spec.actual_fleet_plan.sha256
            && plan["output"] == spec.actual_fleet.path.to_string_lossy().as_ref(),
        "cold185 accepted full fleet/plan/registration binding differs"
    );
    let aggregate =
        current_allocation(&plan, clock)?.context("cold185 genuine fleet allocation absent")?;
    validate_reader_bridge(&plan, &fleet, &aggregate, clock)?;
    let loaded = load_registration(&spec.registration, clock)?;
    ensure!(
        loaded.proof["stage"] == "start-pre",
        "cold185 token acceptance requires actual gated start-pre"
    );
    ensure!(
        spec.numeric_delivery_eta_millis == authenticated_eta(&loaded.proof)?,
        "cold185 fleet acceptance ETA differs from actual authenticated status"
    );
    let event = &loaded.event;
    let iid = text(event, "actor_invocation_id")?;
    ensure!(
        spec.output == Path::new(ROOT).join(iid).join("fleet-acceptance.json"),
        "cold185 fleet acceptance output crossed original invocation"
    );
    let final_clock = super::now()?;
    let final_aggregate =
        current_allocation(&plan, final_clock)?.context("cold185 final genuine task absent")?;
    ensure!(
        final_aggregate == aggregate,
        "cold185 accepted fleet/task changed before proof publication"
    );
    let acceptance = json!({"schema":"horizon-epoch185-native-owner-enrollment-v4","kind":"fleet_enrollment",
        "epoch":185,"actor_unit":event["actor_unit"],"actor_invocation_id":event["actor_invocation_id"],
        "ready_pid":event["ready_pid"],"ready_start_ticks":event["ready_start_ticks"],
        "admission_sha256":event["admission_sha256"],"restarts":0,"phase":"verification",
        "root_operator_owner":true,"actual_start_pre_evidence_accepted":true,
        "numeric_delivery_eta_millis":spec.numeric_delivery_eta_millis,"sampled_at":final_clock,
        "resource_credit_bytes":0,"underlying_accepted_proof":spec.actual_fleet,
        "registration":spec.registration,"task":event["task"],"actual_fleet":spec.actual_fleet,
        "actual_fleet_plan":spec.actual_fleet_plan,"source_bindings":aggregate["source_bindings"],
        "spec":spec_binding,"self_sha256":self_sha,"publication_authorized":false,
        "ordinary_full_replay_authorized":false,"r2_mutations":false});
    super::persist(&spec.output, &acceptance)?;
    println!(
        "{}",
        json!({"fleet_acceptance":spec.output,"epoch":185,"resource_credit_bytes":0})
    );
    Ok(())
}

fn inherited_native_view(
    actual: &BTreeMap<String, Value>,
    event: &Value,
    previous: &Value,
) -> Result<BTreeMap<String, Value>> {
    let mut inherited = actual.clone();
    for key in ["actor_unit", "guard_unit", "timer_unit"] {
        inherited
            .remove(text(event, key)?)
            .context("cold185 complete raw census omitted new owner")?;
    }
    let old = previous["unit_census"]
        .as_object()
        .context("cold185 genuine previous complete native census")?;
    ensure!(
        inherited.keys().collect::<BTreeSet<_>>() == old.keys().collect::<BTreeSet<_>>(),
        "cold185 inherited census projection added or dropped another historical role"
    );
    Ok(inherited)
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    fn binding(name: &str) -> Value {
        json!({"path":format!("/test-only/cold185/{name}.json"),"sha256":"a".repeat(64)})
    }
    fn fixture() -> Loaded {
        let iid = "a".repeat(32);
        let actor = "horizon-qualify-185-capped-cold-test.service";
        let guard = "horizon-guard-185-capped-cold-test.service";
        let timer = "horizon-guard-185-capped-cold-test.timer";
        let mut native = json!({});
        native[actor] = json!({"Id":actor,"InvocationID":iid,"ControlPID":"1234","MainPID":"0",
            "NRestarts":"0","ActiveState":"activating","SubState":"start-pre","MemoryMax":(8u64<<30).to_string()});
        for name in [guard, timer] {
            native[name] = json!({"Id":name,"InvocationID":"","ControlPID":"0","MainPID":"0",
                "NRestarts":"0","ActiveState":"inactive","SubState":"dead","Job":"",
                "MemoryMax":GUARD_MEMORY_BYTES.to_string()});
        }
        let event = json!({"actor_unit":actor,"actor_invocation_id":iid,"guard_unit":guard,"timer_unit":timer,
            "task":binding("task"),"previous_fleet":binding("prior-fleet"),"previous_plan":binding("prior-plan")});
        let proof = json!({"actor_unit":actor,"guard_unit":guard,"timer_unit":timer,
            "limits":{"memory":8u64<<30},"candidate_DATA_bytes":200u64<<30,"minimum_free_bytes":300u64<<30,
            "native":native,"guard_pending":true,"stage":"start-pre",
            "source_bindings":{"admission":binding("admission"),"task":binding("task")}});
        Loaded {
            binding: serde_json::from_value(binding("registration")).unwrap(),
            event,
            proof,
            previous_fleet: json!({"unit_census":{"original199.service":{"MainPID":"2467123"}}}),
            previous_plan: json!({"retain":true}),
        }
    }
    #[test]
    fn pending_guard_is_charged_once_inside_actor_claim_without_an_invented_invocation() {
        let loaded = fixture();
        let rows = allocation_rows(&loaded).unwrap();
        let peers = rows["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0]["memory_max_bytes"],
            (8u64 << 30) + GUARD_MEMORY_BYTES
        );
        assert_eq!(peers[0]["actual_actor_memory_hard_limit_bytes"], 8u64 << 30);
        assert_eq!(peers[0]["reserved_guard_memory_bytes"], GUARD_MEMORY_BYTES);
        assert_eq!(peers[0]["data_reservation_bytes"], 200u64 << 30);
        assert_eq!(peers[0]["native_pool_suballocation"], false);
        assert_eq!(
            rows["native"]["horizon-guard-185-capped-cold-test.service"]["InvocationID"],
            ""
        );
        assert_eq!(rows["guard_pending"], true);
    }
    #[test]
    fn pending_guard_cannot_hide_a_live_queued_or_differently_limited_service() {
        for (field, value) in [
            ("ActiveState", json!("active")),
            ("ControlPID", json!("1")),
            ("MainPID", json!("44")),
            ("Job", json!("35")),
            ("MemoryMax", json!("1")),
        ] {
            let mut loaded = fixture();
            loaded.proof["native"]["horizon-guard-185-capped-cold-test.service"][field] = value;
            assert!(allocation_rows(&loaded).is_err(), "{field}");
        }
    }
    #[test]
    fn missing_or_extra_native_family_and_uncharged_memory_fail_closed() {
        let mut loaded = fixture();
        loaded.proof["native"]
            .as_object_mut()
            .unwrap()
            .remove("horizon-guard-185-capped-cold-test.timer");
        assert!(allocation_rows(&loaded).is_err());
        let mut loaded = fixture();
        loaded.proof["native"]["foreign.service"] = json!({});
        assert!(allocation_rows(&loaded).is_err());
        let mut loaded = fixture();
        loaded.proof["limits"]["memory"] = json!(1);
        assert!(allocation_rows(&loaded).is_err());
        let mut loaded = fixture();
        loaded.proof["candidate_DATA_bytes"] = json!(0);
        assert!(allocation_rows(&loaded).is_err());
    }
    #[test]
    fn original_source_bindings_are_deduplicated_by_exact_path_and_digest() {
        let loaded = fixture();
        let rows = allocation_rows(&loaded).unwrap();
        let bindings = rows["source_bindings"].as_array().unwrap();
        assert_eq!(
            bindings
                .iter()
                .filter(|b| b["path"] == binding("task")["path"])
                .count(),
            1
        );
        assert!(bindings
            .iter()
            .any(|b| b["path"] == binding("admission")["path"]));
        assert!(bindings
            .iter()
            .any(|b| b["path"] == binding("registration")["path"]));
    }
    #[test]
    fn inherited_native_projection_removes_only_the_three_proven_new_roles() {
        let loaded = fixture();
        let mut raw: BTreeMap<String, Value> =
            serde_json::from_value(loaded.proof["native"].clone()).unwrap();
        raw.insert("original199.service".into(), json!({"MainPID":"2467123"}));
        let original = raw.clone();
        let inherited = inherited_native_view(&raw, &loaded.event, &loaded.previous_fleet).unwrap();
        assert_eq!(raw, original);
        assert_eq!(inherited.len(), 1);
        assert_eq!(inherited["original199.service"]["MainPID"], "2467123");
        raw.insert("foreign.service".into(), json!({}));
        assert!(inherited_native_view(&raw, &loaded.event, &loaded.previous_fleet).is_err());
        raw.remove("foreign.service");
        raw.remove("original199.service");
        assert!(inherited_native_view(&raw, &loaded.event, &loaded.previous_fleet).is_err());
    }
}

fn validate_fleet_history(
    fleet: &Value,
    previous: &Value,
    event: &Value,
    registration: &Value,
) -> Result<()> {
    let epochs = fleet["epochs"]
        .as_array()
        .context("cold185 actual full fleet epoch census")?;
    ensure!(
        epochs.len() == 100
            && epochs
                .iter()
                .map(|row| row["epoch"].as_u64())
                .eq((101..=200).map(Some))
            && fleet["inventory"]["anomalies"] == 0,
        "cold185 accepted fleet dropped epoch history or records an inventory anomaly"
    );
    let old = previous["diagnostics"]
        .as_array()
        .context("cold185 previous full diagnostics")?;
    let current = fleet["diagnostics"]
        .as_array()
        .context("cold185 actual full diagnostics")?;
    ensure!(
        current.len() == old.len() + 1,
        "cold185 actual fleet dropped or added another diagnostic"
    );
    for prior in old {
        ensure!(
            current
                .iter()
                .filter(|row| row["epoch"] == prior["epoch"]
                    && row["unit"]["Id"] == prior["unit"]["Id"]
                    && row["launch_invocation_id"] == prior["launch_invocation_id"]
                    && row["launch_receipt"] == prior["launch_receipt"]
                    && row["launch_receipt_sha256"] == prior["launch_receipt_sha256"])
                .count()
                == 1,
            "cold185 actual fleet changed a retained original diagnostic"
        );
    }
    ensure!(
        current
            .iter()
            .filter(|row| row["epoch"] == 185
                && row["unit"]["Id"] == event["actor_unit"]
                && row["launch_invocation_id"] == event["actor_invocation_id"]
                && row["launch_receipt"] == registration["path"]
                && row["launch_receipt_sha256"] == registration["sha256"]
                && row["live"] == true)
            .count()
            == 1,
        "cold185 actual fleet omitted exact active start-pre registration"
    );
    let old_pipelines = previous["pipelines"]
        .as_array()
        .context("cold185 old pipeline census")?;
    let pipelines = fleet["pipelines"]
        .as_array()
        .context("cold185 full actual pipeline census")?;
    ensure!(
        pipelines.len() == old_pipelines.len(),
        "cold185 actual fleet dropped pipeline history"
    );
    for prior in old_pipelines {
        ensure!(
            pipelines
                .iter()
                .filter(|row| row["epoch"] == prior["epoch"]
                    && row["phase"] == prior["phase"]
                    && row["unit"]["Id"] == prior["unit"]["Id"]
                    && row["expected_invocation_id"] == prior["expected_invocation_id"]
                    && row["evidence"] == prior["evidence"])
                .count()
                == 1,
            "cold185 actual fleet changed another pipeline claim or its evidence"
        );
    }
    Ok(())
}

#[cfg(test)]
mod long_reader_clock_tests {
    use super::*;
    #[test]
    fn original_registration_survives_real204_second_reader_without_resetting_ready_deadline() {
        let iid = "a".repeat(32);
        let binding = json!({"path":format!("{ENROLLMENT_ROOT}/{iid}/registration.json"),"sha256":"b".repeat(64)});
        let source = json!({"path":"/test-only/source.json","sha256":"c".repeat(64)});
        let event = json!({"schema":SCHEMA,"epoch":185,"phase":"verification","actor_unit":"actor.service",
            "guard_unit":"guard.service","timer_unit":"guard.timer","actor_invocation_id":iid,
            "ready_pid":44,"ready_start_ticks":55,"ready_started_at":1000,"sampled_at":1002,
            "setup_deadline_at":1600,"task":source,"previous_fleet":source,"observer":source,
            "resource_credit_bytes":0,"ordinary_full_replay_authorized":false,"publication_authorized":false,"r2_mutations":false});
        event_shape(&event, &binding, 1206).unwrap();
        assert_eq!(event["ready_started_at"], 1000);
        assert_eq!(event["sampled_at"], 1002);
        assert!(event_shape(&event, &binding, 1600).is_err());
        let mut extended = event.clone();
        extended["setup_deadline_at"] = json!(1601);
        assert!(event_shape(&extended, &binding, 1206).is_err());
    }
}

fn inherited185_terminal(previous: &Value, claim: &Value, pipeline: bool) -> Result<()> {
    let unit = text(claim, "unit")?;
    let rows = previous[if pipeline { "pipelines" } else { "diagnostics" }]
        .as_array()
        .context("cold185 inherited185 claim census")?;
    let selected = rows
        .iter()
        .filter(|row| row["epoch"] == 185 && row["unit"]["Id"] == unit)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1 && selected[0]["live"] == false,
        "cold185 replacement overlaps an inherited live185 claim"
    );
    let native = &previous["unit_census"][unit];
    ensure!(
        native["Id"] == unit
            && native["ActiveState"] == "inactive"
            && native["SubState"] == "dead"
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["Job"] == ""
            && native["NRestarts"] == "0",
        "cold185 inherited185 claim lacks exact completed native closure"
    );
    Ok(())
}

fn authenticated_eta(proof: &Value) -> Result<u64> {
    let status = super::native::read_json(&checked_binding(&proof["current_task"])?, 4 << 20)?;
    ensure!(
        status["schema"] == "horizon-status-only-correction-v1"
            && status["epoch"] == 185
            && status["authenticated_readback"] == true
            && status["after_status"]["epoch"] == 185
            && status["after_status"]["phase"] == "verification",
        "cold185 numeric estimate has no genuine authenticated source"
    );
    let eta = integer(&status["after_status"], "estimated_remaining_millis")?;
    ensure!(
        eta > 0,
        "cold185 active task requires positive numeric delivery ETA"
    );
    Ok(eta)
}

#[cfg(test)]
mod complete_fleet_tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Value) {
        let registration = json!({"path":"/test-only/registration.json","sha256":"a".repeat(64)});
        let event = json!({"actor_unit":"actor185.service","actor_invocation_id":"b".repeat(32)});
        let old_diag = json!({"epoch":145,"unit":{"Id":"original145.service"},"launch_invocation_id":"c".repeat(32),
            "launch_receipt":"/test-only/original145.json","launch_receipt_sha256":"d".repeat(64)});
        let pipeline = json!({"epoch":141,"phase":"original-repair","unit":{"Id":"original141.service"},
            "expected_invocation_id":"e".repeat(32),"evidence":[{"path":"/test-only/old.json","sha256":"f".repeat(64)}]});
        let previous = json!({"diagnostics":[old_diag],"pipelines":[pipeline]});
        let current = json!({"epochs":(101..=200).map(|epoch|json!({"epoch":epoch,"state":"failed-needs-repair"})).collect::<Vec<_>>(),
            "inventory":{"anomalies":0},"pipelines":previous["pipelines"],
            "diagnostics":[previous["diagnostics"][0],{"epoch":185,"unit":{"Id":event["actor_unit"]},
            "launch_invocation_id":event["actor_invocation_id"],"launch_receipt":registration["path"],
            "launch_receipt_sha256":registration["sha256"],"live":true}]});
        (current, previous, event, registration)
    }
    #[test]
    fn actual_complete_fleet_preserves_all_epoch_and_original_owner_rows() {
        let (fleet, old, event, registration) = fixture();
        validate_fleet_history(&fleet, &old, &event, &registration).unwrap();
        for pointer in ["/diagnostics", "/pipelines", "/epochs"] {
            let mut broken = fleet.clone();
            broken
                .pointer_mut(pointer)
                .unwrap()
                .as_array_mut()
                .unwrap()
                .pop();
            assert!(
                validate_fleet_history(&broken, &old, &event, &registration).is_err(),
                "{pointer}"
            );
        }
        let mut broken = fleet.clone();
        broken["diagnostics"][0]["launch_invocation_id"] = json!("a".repeat(32));
        assert!(validate_fleet_history(&broken, &old, &event, &registration).is_err());
        let mut broken = fleet.clone();
        broken["pipelines"][0]["evidence"] = json!([]);
        assert!(validate_fleet_history(&broken, &old, &event, &registration).is_err());
        let mut broken = fleet.clone();
        broken["inventory"]["anomalies"] = json!(1);
        assert!(validate_fleet_history(&broken, &old, &event, &registration).is_err());
    }
    #[test]
    fn retained_terminal185_history_is_kept_but_live_or_queued_predecessor_rejects() {
        let claim = json!({"epoch":185,"unit":"original185.service"});
        let old = json!({"diagnostics":[{"epoch":185,"unit":{"Id":"original185.service"},"live":false}],
            "unit_census":{"original185.service":{"Id":"original185.service","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","ControlPID":"0","NRestarts":"0","Job":""}}});
        inherited185_terminal(&old, &claim, false).unwrap();
        for (key, value) in [
            ("MainPID", json!("33")),
            ("ControlPID", json!("22")),
            ("Job", json!("77")),
            ("ActiveState", json!("active")),
        ] {
            let mut broken = old.clone();
            broken["unit_census"]["original185.service"][key] = value;
            assert!(
                inherited185_terminal(&broken, &claim, false).is_err(),
                "{key}"
            );
        }
        let mut broken = old.clone();
        broken["diagnostics"][0]["live"] = json!(true);
        assert!(inherited185_terminal(&broken, &claim, false).is_err());
    }
}

impl FleetRoute {
    pub(in crate::fleet) fn retained(&self) -> bool {
        self.retained
    }
    pub(in crate::fleet) fn phase(&self) -> &str {
        if self.aggregate["stage"] == "running" {
            "cold185-private-prefix-replay"
        } else {
            "cold185-held-start-pre"
        }
    }
    pub(in crate::fleet) fn legacy_previous(&self, previous: &Value) -> Result<Value> {
        if self.retained {
            super::lifecycle::project_fleet(
                previous,
                &self.event,
                &self.aggregate["prior_fleet_value"],
            )
        } else {
            Ok(previous.clone())
        }
    }
    pub(in crate::fleet) fn projected_plan(&self, raw: &Value) -> Result<Value> {
        if self.retained {
            super::lifecycle::project_plan(
                raw,
                &self.event,
                &self.aggregate["prior_fleet_plan_value"],
            )
        } else {
            Ok(raw.clone())
        }
    }
}
fn validate_retained_reader_bridge(
    plan: &Value,
    fleet: &Value,
    aggregate: &Value,
    loaded: &Loaded,
    clock: u64,
) -> Result<()> {
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet[FIELD] == json!(loaded.binding)
            && fleet[super::lifecycle::FIELD] == plan[super::lifecycle::FIELD]
            && fleet[super::lifecycle::TERMINAL_FIELD] == plan[super::lifecycle::TERMINAL_FIELD]
            && fleet["observer_receipt"] == plan["observer"]["path"]
            && fleet["observer_sha256"] == plan["observer"]["sha256"]
            && fleet["producer_mutations"] == false
            && fleet["remote_mutations"] == false
            && fleet["publication_authorized"] == false
            && fleet["resource_admission_authorized"] == false,
        "cold185 retained reader lacks actual current fleet/observer/lifecycle and complete promises"
    );
    let current_plan =
        checked_binding(&json!({"path":fleet["plan"],"sha256":fleet["plan_sha256"]}))?;
    ensure!(
        bound_json(&current_plan)? == *plan,
        "cold185 retained reader crossed current complete plan"
    );
    let observer = bound_json(&checked_binding(&plan["observer"])?)?;
    ensure!(
        observer["recorded_at_utc"] == fleet["sampled_at_utc"],
        "cold185 retained observer sample differs"
    );
    let previous = bound_json(&checked_binding(&plan["previous_fleet"])?)?;
    let event = bound_json(&checked_binding(&plan["metadata_event"])?)?;
    validate_transition(
        &previous,
        plan,
        &event,
        text(fleet, "sampled_at_utc")?,
        clock,
    )?;
    let accepted = &fleet["cold185_allocation"];
    crate::fleet::epoch186::accounting::cold185_rollover::compare_allocations(accepted, aggregate)?;
    let census = fleet["unit_census"]
        .as_object()
        .context("cold185 retained accepted raw census")?;
    for (name, native) in accepted["native"]
        .as_object()
        .context("cold185 retained accepted native proof")?
    {
        ensure!(
            census.get(name) == Some(native),
            "cold185 retained fleet raw native evidence differs from its actual allocation endpoint"
        );
    }
    Ok(())
}
