//! Root-only static replay of genuine captured metadata through accepted().
//! No service census, resource observation, output, or admission occurs here.
use super::super::*;
use serde::Deserialize;
#[derive(Deserialize)]
struct Sources {
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    completion: BoundFile,
    resource_parent: BoundFile,
    phase_events: Vec<EventBinding>,
    reader191: BoundFile,
    transfer191: BoundFile,
    correction191: BoundFile,
    closed185: BoundFile,
    standing: BoundFile,
    guards: Vec<GuardSpec>,
}
struct Actual {
    sources: Sources,
    values: std::collections::BTreeMap<&'static str, Value>,
    events: Vec<Value>,
    frame_index: usize,
    original_time: u64,
}
impl Actual {
    fn load() -> Self {
        let manifest: BoundFile=serde_json::from_str(&std::env::var("JETSTREAMER_CURRENT_TERMINAL145_FIXTURE_BINDING").expect("Root must bind the actual post-capture fixture manifest")).unwrap();
        let fixture=accounting::protected_generated(&manifest).unwrap();
        let spec:BoundFile=serde_json::from_value(fixture["reader_spec"].clone()).unwrap();
        let raw=accounting::protected_generated(&spec).unwrap();
        let sources: Sources = serde_json::from_value(raw["resource_accounting"].clone()).unwrap();
        let mut values = std::collections::BTreeMap::new();
        for (key, bound) in [
            ("observer", &sources.observer),
            ("fleet", &sources.fleet),
            ("fleet_plan", &sources.fleet_plan),
            ("completion", &sources.completion),
            ("parent", &sources.resource_parent),
            ("reader", &sources.reader191),
            ("transfer", &sources.transfer191),
            ("correction", &sources.correction191),
            ("closed185", &sources.closed185),
            ("standing", &sources.standing),
        ] {
            values.insert(key, accounting::protected_generated(bound).unwrap());
        }
        // Use production custody dispatch for every actual historical event.
        let events: Vec<Value> = sources
            .phase_events
            .iter()
            .map(|e| accounting::phase_event_source(&e.source).unwrap())
            .collect();
        let selected: Vec<usize> = sources
            .phase_events
            .iter()
            .enumerate()
            .filter(|(_, e)| e.schema == contract::SCHEMA)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(selected.len(), 1);
        let frame_index = selected[0];
        let accepted = fixture;
        assert_eq!(
            binding(&sources.phase_events[frame_index].source),
            accepted["frame"]
        );
        assert_eq!(
            events[frame_index]["self_sha256"],
            CURRENT_TERMINAL145_FRAME_CAPTURE_SHA.unwrap()
        );
        let original_time = events[frame_index]["recorded_unix_seconds"]
            .as_u64()
            .unwrap();
        Self {
            sources,
            values,
            events,
            frame_index,
            original_time,
        }
    }
    fn frame(&self) -> &Value {
        &self.events[self.frame_index]
    }
    fn frame_mut(&mut self) -> &mut Value {
        &mut self.events[self.frame_index]
    }
    fn check(&self) -> Result<bool> {
        let s = &self.sources;
        let spec = accounting::SpecView {
            observer: &s.observer,
            fleet: &s.fleet,
            fleet_plan: &s.fleet_plan,
            completion: &s.completion,
            resource_parent: &s.resource_parent,
            phase_events: &s.phase_events,
            reader191: &s.reader191,
            transfer191: &s.transfer191,
            correction191: &s.correction191,
            closed185: &s.closed185,
            guards: &s.guards,
            allow_retained144_terminal: true,
        };
        let b = accounting::BundleView {
            observer: &self.values["observer"],
            fleet: &self.values["fleet"],
            fleet_plan: &self.values["fleet_plan"],
            completion: &self.values["completion"],
            parent: &self.values["parent"],
            events: &self.events,
            reader: &self.values["reader"],
            transfer: &self.values["transfer"],
            correction: &self.values["correction"],
            closed185: &self.values["closed185"],
            standing: &self.values["standing"],
        };
        // Executes the actual reader's adapter, every source loader, typed-bridge
        // consumer contract. The outer basis also performs unrelated live assembly
        // observations, so it is deliberately outside this static regression.
        accepted(&spec, &b, self.original_time)
    }
}

#[test]
#[ignore = "Root must first bind actual v3 CLI capture and its exact reader-spec fixture"]
fn genuine_current_terminal145_capture_reaches_complete_outer_adapter_and_rejects_tampering() {
    let mut actual=Actual::load();
    let saved=serde_json::to_value((&actual.events,&actual.values)).unwrap();
    assert!(actual.check().unwrap());
    assert_eq!(actual.frame()["self_sha256"],CURRENT_TERMINAL145_FRAME_CAPTURE_SHA.unwrap());
    assert_eq!(actual.frame()["live145_prefix_guard_history"].as_array().unwrap().len(),2);
    let context:original199_input_witness_consumer::Bound=serde_json::from_value(actual.values["fleet_plan"]["epoch199_terminal_context"].clone()).unwrap();
    assert!(original199_input_witness_consumer::is_selected_context(&context));
    for (key,value) in [("self_sha256",serde_json::json!("f".repeat(64))),
        ("native_census_after",serde_json::json!({"foreign":true})),
        ("live145_prefix_guard_history",serde_json::json!([])),
        ("publication_authorized",serde_json::json!(true)),
        ("full_routine_completion_claimed",serde_json::json!(true)),
        ("new_resource_observations",serde_json::json!(1)),
        ("epoch199_terminal_context",Value::Null),
        ("bindings",serde_json::json!({"foreign":true}))] {
        let prior=actual.frame().get(key).cloned();actual.frame_mut()[key]=value;
        assert!(actual.check().is_err(),"{key}");
        match prior {Some(value)=>actual.frame_mut()[key]=value,None=>{actual.frame_mut().as_object_mut().unwrap().remove(key);}}
    }
    for pointer in ["/live145_prefix_guard_history/0/actor_native/InvocationID",
        "/live145_prefix_guard_history/0/actor_native/NRestarts",
        "/live145_prefix_guard_history/0/token/actor_iid"] {
        let original=actual.frame().pointer(pointer).expect("genuine terminal145 capture field").clone();
        *actual.frame_mut().pointer_mut(pointer).unwrap()=serde_json::json!("crossed");
        assert!(actual.check().is_err(),"{pointer}");
        *actual.frame_mut().pointer_mut(pointer).unwrap()=original;
    }
    assert!(actual.check().unwrap());
    assert_eq!(saved,serde_json::to_value((&actual.events,&actual.values)).unwrap());
}
