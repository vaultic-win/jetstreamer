//! Semantic read-only regressions against original0558 metadata, at its original clock.
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
        include_bytes!("sealed-alias0558-fixtures/acceptance.json"),
        "7c8ef323801619d3c11d4abe5346a3fba7623f628c764e81902202795ad2e654",
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
            include_bytes!("sealed-alias0558-fixtures/reader-spec.json"),
            "4b15aeecded3822595c80ad8cae41c2c435edb3648f85cd29a601cd7043a72be",
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
            SEALED_ALIAS_PREDECESSOR_FRAME_CAPTURE_SHA.unwrap()
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
fn actual0558_writer_and_image_have_genuine_native_success_and_normal_seal() {
    let a = acceptance();
    let cli = fixture(
        include_bytes!("sealed-alias0558-fixtures/cli-proof.json"),
        "ec87c7b1d58fa371478a12c5b79278a4363344c62752747400bb872fcf23b421",
    );
    let seal = fixture(
        include_bytes!("sealed-alias0558-fixtures/cli-seal.json"),
        "13f6b975ad3d2927696fc681ef4debb1d7ea94ec844ebb499d1069e19beea2c4",
    );
    let library = fixture(
        include_bytes!("sealed-alias0558-fixtures/library-proof.json"),
        "f571ecf0908da7daa58f062c0455f3319e5dace8a37bc8622b102177b3555bad",
    );
    let pin = SEALED_ALIAS_PREDECESSOR_FRAME_CAPTURE_SHA.unwrap();
    assert_eq!(
        a["actual_completed_writer"]["InvocationID"],
        "367b149f1acc4dcf81a18c8f90008f71"
    );
    for (key, value) in [
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
    ] {
        assert_eq!(a["actual_completed_writer"][key], value);
    }
    assert_eq!(
        a["frame"]["sha256"],
        "becedbaf4cacec8fbee0d121a2474aebc6a6a2bf51ac27c73706e72f5cff32c6"
    );
    assert_eq!(cli["artifact"]["sha256"], pin);
    assert_eq!(cli["ordinary_tests_passed"], 50);
    assert_eq!(cli["native_saved_custody_actual_cases_passed"], 1);
    assert_eq!(library["ordinary_tests_passed"], 432);
    assert_eq!(
        library["production_artifact"]["sha256"],
        "edd3b6531376444f2bbc30b8c858cd1ec9770ef832bb4d7d4eafc64b4a31fa0b"
    );
    assert_eq!(
        seal["members"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["name"] == "jetstreamer-horizon-frame" && m["sha256"] == pin)
            .count(),
        1
    );
    assert_eq!(a["memory_credit_bytes"], 0);
    assert_eq!(a["DATA_credit_bytes"], 0);
    assert_eq!(a["replay_admission_authorized"], false);
}
#[test]
fn exact0558_image_reaches_all_shared_registration_gates_and_preserves_old_dispatch() {
    let actual = Actual::load();
    let frame = actual.frame();
    assert!(typed_bridge_capture(frame));
    assert!(qualified_retry0005_capture(frame));
    assert!(qualified_cached145_capture(frame));
    assert!(!ordinary199_capture(frame));
    assert!(!canonical_v5_capture(frame));
    assert!(!retained199_v2_capture(frame));
    for pin in [
        TYPED_FLEET_BRIDGE_FRAME_CAPTURE_SHA,
        TERMINAL145_ANCESTRY_FRAME_CAPTURE_SHA,
        CLOSED145_FAMILY_FRAME_CAPTURE_SHA,
        CLOSED145_INACTIVE_TIMER_RELOAD_CAPTURE_SHA,
        ACCEPTED0428_REFRESH_FRAME_CAPTURE_SHA,
    ] {
        assert!(typed_bridge_capture(&json!({"self_sha256":pin.unwrap(),
            "epoch199_terminal_context":retained199_v2_selector()})));
    }
    assert!(!typed_bridge_capture_with_pin(frame, None));
    assert!(!typed_bridge_capture(&json!({"self_sha256":"f".repeat(64),
        "epoch199_terminal_context":retained199_v2_selector()})));
}
#[test]
fn original0558_complete_reader_frame_adapter_passes_full_typed_consumer_at_original_clock() {
    let actual = Actual::load();
    let before = serde_json::to_value((&actual.events, &actual.values, &actual.current_fleet_plan)).unwrap();
    assert!(actual.check().unwrap());
    assert_eq!(
        before,
        serde_json::to_value((&actual.events, &actual.values, &actual.current_fleet_plan)).unwrap()
    );
}
#[test]
fn complete0558_reader_rejects_unknown_image_policy_scope_binding_and_consumer_damage() {
    let mut actual = Actual::load();
    for (key, value) in [
        ("self_sha256", json!("f".repeat(64))),
        ("epoch199_terminal_context", Value::Null),
        (
            "epoch199_http500_capture_registration",
            json!({"foreign":true}),
        ),
        (
            "epoch199_http500_recovery_enrollment",
            json!({"foreign":true}),
        ),
        ("epoch199_promises", Value::Null),
        ("native_census_after", json!({"foreign":true})),
        ("publication_authorized", json!(true)),
    ] {
        let original = actual.frame().get(key).cloned();
        actual.frame_mut()[key] = value;
        assert!(actual.check().is_err(), "{key}");
        match original {
            Some(value) => actual.frame_mut()[key] = value,
            None => {
                actual.frame_mut().as_object_mut().unwrap().remove(key);
            }
        }
    }
    let i = actual.frame_index;
    let original_clock = actual.sources.phase_events[i].clock_pointer.clone();
    actual.sources.phase_events[i].clock_pointer = "/foreign".into();
    assert!(actual.check().is_err());
    actual.sources.phase_events[i].clock_pointer = original_clock;
    assert!(actual.sources.phase_events[i].owners.is_empty());
    actual.sources.phase_events[i].owners.push(
        serde_json::from_value(json!({
            "manager_pointer":"/foreign", "rss_pointer":null, "launch":null,
            "role":"delivery", "first_epoch":101, "last_epoch":200
        }))
        .unwrap(),
    );
    assert!(actual.check().is_err());
    actual.sources.phase_events[i].owners.clear();
    let original = actual.frame()["bindings"]["observer"].clone();
    actual.frame_mut()["bindings"]["observer"]["sha256"] = json!("f".repeat(64));
    assert!(actual.check().is_err());
    actual.frame_mut()["bindings"]["observer"] = original;
    let original = actual.current_fleet_plan["epoch199_terminal_context"].clone();
    for selector in [Value::Null,
        json!({"path":"/neighbor/context.json","sha256":"a".repeat(64)}),
        json!({"path":original["path"],"sha256":"a".repeat(64)})] {
        actual.current_fleet_plan["epoch199_terminal_context"] = selector;
        assert!(actual.check().is_err());
    }
    actual.current_fleet_plan["epoch199_terminal_context"] = original;
    actual.check().unwrap();
}
