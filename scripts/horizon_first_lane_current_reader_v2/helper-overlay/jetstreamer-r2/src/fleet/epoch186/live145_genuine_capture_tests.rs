//! Semantic read-only regressions against genuine1328r2 metadata, at its original clock.
//! Only current test evidence selects the qualified original199 witness wrapper.
//! Accepted Frames, source bindings and original values stay raw.
//! No current resource observation, native start, output, admission, or credit.
use super::*;
use serde::Deserialize;

fn fixture(raw: &[u8], expected: &str) -> Value {
    assert_eq!(format!("{:x}", sha2::Sha256::digest(raw)), expected);
    serde_json::from_slice(raw).unwrap()
}
fn acceptance() -> Value {
    fixture(
        include_bytes!("live145-genuine-frame-fixtures/acceptance.json"),
        "65ec7c664240db07c23ea55c8421d4e812108a9a5bb2570dcb5c63548d8f6b1f",
    )
}
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
    // Current consumer selection is separate from every loaded original value.
    current_fleet_plan: Value,
    frame_index: usize,
    original_time: u64,
}
impl Actual {
    fn load() -> Self {
        let raw = fixture(
            include_bytes!("live145-genuine-frame-fixtures/reader-spec.json"),
            "796288cf53e5beb8f99e4d763d77c73d674f876e068c6f950b8cebde02961f74",
        );
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
        let accepted = acceptance();
        assert_eq!(
            binding(&sources.phase_events[frame_index].source),
            accepted["frame"]
        );
        assert_eq!(
            events[frame_index]["self_sha256"],
            LIVE145_CENSUS_FRAME_CAPTURE_SHA.unwrap()
        );
        let original_time = events[frame_index]["recorded_unix_seconds"]
            .as_u64()
            .unwrap();
        let mut current_fleet_plan = values["fleet_plan"].clone();
        assert_eq!(current_fleet_plan["epoch199_terminal_context"], retained199_v2_selector());
        current_fleet_plan["epoch199_terminal_context"] = json!({
            "path":"/usr/local/lib/jetstreamer/horizon-original199-witness-context-20261107-v1/context.json",
            "sha256":"4d45cbd0e71ca8cf591cfd3c435c4b798178de308faaa80a0b262fa9322374c7"
        });
        // Neither the accepted historical Frame nor its original plan is rebased.
        let mut restored = current_fleet_plan.clone();
        restored["epoch199_terminal_context"] = retained199_v2_selector();
        assert_eq!(restored, values["fleet_plan"]);
        Self {
            sources,
            values,
            current_fleet_plan,
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
            fleet_plan: &self.current_fleet_plan,
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
fn genuine1328r2_frame_reaches_complete_reader_adapter_and_new_typed_library() {
 let actual=Actual::load(); let before=serde_json::to_value((&actual.events,&actual.values,&actual.current_fleet_plan)).unwrap();
 assert!(actual.check().unwrap());
 assert_eq!(before,serde_json::to_value((&actual.events,&actual.values,&actual.current_fleet_plan)).unwrap());
 assert_eq!(actual.frame()["self_sha256"],"454ca6069a17ab9d917f59324a9c318dddb8c31203f5a753cb8070ee3efefec5");
 assert_eq!(actual.frame()["live145_prefix_guard_history"].as_array().unwrap().len(),2);
}
#[test]
fn complete_reader_rejects_unknown_image_and_changed_live145_native_envelope() {
 let mut actual=Actual::load();
 for (key,value) in [("self_sha256",json!("f".repeat(64))),("native_census_after",json!({"foreign":true})),("live145_prefix_guard_history",json!([])),("publication_authorized",json!(true)),("epoch199_terminal_context",Value::Null)] {
  let prior=actual.frame().get(key).cloned();actual.frame_mut()[key]=value;assert!(actual.check().is_err(),"{key}");
  match prior {Some(v)=>{actual.frame_mut()[key]=v;},None=>{actual.frame_mut().as_object_mut().unwrap().remove(key);}}
 }
 let original = actual.current_fleet_plan["epoch199_terminal_context"].clone();
 for selector in [Value::Null,
  json!({"path":"/neighbor/context.json","sha256":"a".repeat(64)}),
  json!({"path":original["path"],"sha256":"a".repeat(64)})] {
  actual.current_fleet_plan["epoch199_terminal_context"] = selector;
  assert!(actual.check().is_err());
 }
 actual.current_fleet_plan["epoch199_terminal_context"] = original;
 assert!(actual.check().unwrap());
}
#[test]
fn native_capture_and_both_new_artifacts_have_genuine_success_and_normal_seals() {
 let accepted=acceptance();
 assert_eq!(accepted["actual_completed_writer"]["InvocationID"],"f943458d0d2143439c2e7d1c28e3c8ea");
 for (key,value) in [("Result","success"),("ExecMainStatus","0"),("MainPID","0"),("ControlPID","0"),("NRestarts","0")] {assert_eq!(accepted["actual_completed_writer"][key],value);}
 assert_eq!(accepted["replay_admission_authorized"],false);assert_eq!(accepted["memory_credit_bytes"],0);assert_eq!(accepted["DATA_credit_bytes"],0);
 let cli_proof=fixture(include_bytes!("live145-genuine-frame-fixtures/cli-proof.json"),"a920e23650508f3283c352b43aca81ff93343e037fa747102eafc8690a960cad");
 let cli_seal=fixture(include_bytes!("live145-genuine-frame-fixtures/cli-seal.json"),"9e0e5e27fef5f3ec4b24e1faca1669f9472f74d0a3c89472c4d415a760217b94");
 let library_proof=fixture(include_bytes!("live145-genuine-frame-fixtures/library-proof.json"),"72ca4ff61582f6a0a4f0c96c45abbbc2e0febdd9ceec48d5d7aa973879f41e54");
 let library_seal=fixture(include_bytes!("live145-genuine-frame-fixtures/library-seal.json"),"163d66a22b1018c0122bc24682b38d8b26b91db60f35396a25339aeb39609d10");
 assert_eq!(cli_proof["production_artifact"]["sha256"],LIVE145_CENSUS_FRAME_CAPTURE_SHA.unwrap());
 assert_eq!(library_proof["production_artifact"]["sha256"],"664a54f1a362c7d806f7f207414cb05bb9eec694f8421cca9c96fc7bb73ca604");
 for (seal,name,digest) in [(&cli_seal,"jetstreamer-horizon-frame",LIVE145_CENSUS_FRAME_CAPTURE_SHA.unwrap()),(&library_seal,"libhorizon_recovered_resource_frame_typed_bridge_v1.rlib","664a54f1a362c7d806f7f207414cb05bb9eec694f8421cca9c96fc7bb73ca604")] {assert_eq!(seal["members"].as_array().unwrap().iter().filter(|m|m["name"]==name && m["sha256"]==digest).count(),1);}
}
