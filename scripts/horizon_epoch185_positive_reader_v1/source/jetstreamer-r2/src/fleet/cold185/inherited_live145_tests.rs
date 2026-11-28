//! Historical composition controls, not the failed native whole-host census.
use super::inherited_live145::previous as projected_previous;
use super::*;
use horizon_recovered_resource_frame_typed_bridge_v1::live145_frame as contract;
fn parsed(raw: &str, expected: &str) -> Value {
    assert_eq!(hex_lower(&Sha256::digest(raw.as_bytes())), expected);
    serde_json::from_str(raw).unwrap()
}
fn fixture() -> (Value, Value, Value) {
    let prior = parsed(
        include_str!("inherited_live145_fixtures/prior-fleet.json"),
        "4587d110a43837d2f935f62ace9d76eadff459a0230365a533e626b84a5a5dda",
    );
    let plan = parsed(
        include_str!("inherited_live145_fixtures/prior-plan.json"),
        "b5beb5994251d878388d49ac3918cd8f94fe4422317cb5d37fba77d4d5665653",
    );
    let task = parsed(
        include_str!("inherited_live145_fixtures/original-task.json"),
        "7a8d56f596f71d9ad4b70153bf97f016308c68624bf6b10675550f2b35cba4bc",
    );
    assert_eq!(
        prior["plan_sha256"],
        "b5beb5994251d878388d49ac3918cd8f94fe4422317cb5d37fba77d4d5665653"
    );
    assert_eq!(
        task["actor_invocation_id"],
        "dff3a3ef94d943b0bae94634fa9dfc50"
    );
    assert_eq!(task["stage"], "start-pre");
    (prior, plan, task)
}
fn route(prior: &Value, plan: &Value, task: &Value) -> FleetRoute {
    FleetRoute {
        inherited: serde_json::from_value(plan.clone()).unwrap(),
        inherited_bound: BoundFile {
            path: PathBuf::from(prior["plan"].as_str().unwrap()),
            sha256: prior["plan_sha256"].as_str().unwrap().into(),
        },
        aggregate: json!({"prior_fleet_value":prior,"prior_fleet_plan_value":plan}),
        event: task.clone(),
        retained: false,
    }
}
#[test]
fn ordinary_prior_without_selected_family_remains_byte_for_byte_unchanged() {
    let plan = json!({"tracked_units":["unrelated.service"]});
    let prior = json!({"unit_census":{"unrelated.service":{"Id":"unrelated.service","MemoryMax":"123"}},"raw_history":{"retained":true}});
    assert_eq!(projected_previous(&plan, &prior).unwrap(), prior);
}
#[test]
fn unselected_or_partial_prior_cannot_claim_or_silently_remove_live145() {
    let plan = json!({"tracked_units":["unrelated.service"]});
    let mut prior = json!({"unit_census":{},(contract::FIELD):[]});
    assert!(projected_previous(&plan, &prior).is_err());
    prior.as_object_mut().unwrap().remove(contract::FIELD);
    prior["unit_census"][contract::FAMILY[0]] = json!({"Id":contract::FAMILY[0]});
    assert!(projected_previous(&plan, &prior).is_err());
    let partial = json!({"tracked_units":[contract::FAMILY[0]]});
    assert!(projected_previous(&partial, &prior).is_err());
}
#[test]
#[ignore = "Root readonly genuine2300 recorded145 history and original185task metadata composition"]
fn actual2300_composed_route_projects_both_sides_and_preserves_every_raw_row() {
    let (prior, plan, task) = fixture();
    let original_prior = prior.clone();
    let original_plan = plan.clone();
    let expected = projected_previous(&plan, &prior).unwrap();
    let old: BTreeMap<String, Value> =
        serde_json::from_value(prior["unit_census"].clone()).unwrap();
    let expected_native: BTreeMap<String, Value> =
        serde_json::from_value(expected["unit_census"].clone()).unwrap();
    assert_eq!(old.len(), expected_native.len() + 3);
    for name in contract::FAMILY {
        assert!(old.contains_key(name));
        assert!(!expected_native.contains_key(name));
    }
    let h = prior[contract::FIELD].as_array().unwrap();
    let route = route(&prior, &plan, &task);
    // Each case is explicitly COMPOSED historical metadata. It is not an
    // original failed full native census or an invocation-state observation.
    for (label, task_endpoint, history_endpoint) in [
        ("before", "native_before", 0),
        ("after", "native_after", 1),
        ("normalized-after", "native_after", 1),
    ] {
        let mut composed = old.clone();
        let new: BTreeMap<String, Value> =
            serde_json::from_value(task[task_endpoint].clone()).unwrap();
        assert_eq!(new.len(), 3);
        for (name, row) in new {
            assert!(composed.insert(name, row).is_none());
        }
        let saved = composed.clone();
        let comparison =
            contract::comparison_native(&plan, &composed, Some(&h[history_endpoint])).unwrap();
        assert!(
            inherited_native_view(&comparison, &task, &prior).is_err(),
            "old raw prior unexpectedly accepted {label}"
        );
        let actual = route.inherited_native(&comparison).unwrap();
        assert_eq!(actual, expected_native, "{label}");
        assert_eq!(composed, saved);
        for (name, row) in &expected_native {
            assert_eq!(&actual[name], row);
        }
    }
    assert_eq!(prior, original_prior);
    assert_eq!(plan, original_plan);
    assert_eq!(expected[contract::FIELD], prior[contract::FIELD]);
}
#[test]
#[ignore = "Root readonly genuine2300 recorded145 history tamper rejections"]
fn actual2300_history_or_raw_family_tampering_never_authorizes_projection() {
    let (prior, plan, _) = fixture();
    let mut bad = prior.clone();
    bad.as_object_mut().unwrap().remove(contract::FIELD);
    assert!(projected_previous(&plan, &bad).is_err());
    for count in [0, 1, 3] {
        let mut bad = prior.clone();
        bad[contract::FIELD] = json!(vec![prior[contract::FIELD][0].clone(); count]);
        assert!(projected_previous(&plan, &bad).is_err());
    }
    let mut bad = prior.clone();
    bad[contract::FIELD].as_array_mut().unwrap().swap(0, 1);
    assert!(projected_previous(&plan, &bad).is_err());
    let mut bad = prior.clone();
    bad[contract::FIELD][1]["actor_native"]["InvocationID"] = json!("f".repeat(32));
    assert!(projected_previous(&plan, &bad).is_err());
    let mut bad = prior.clone();
    bad["unit_census"][contract::FAMILY[0]]["InvocationID"] = json!("f".repeat(32));
    assert!(projected_previous(&plan, &bad).is_err());
    let mut bad = prior.clone();
    bad["unit_census"]
        .as_object_mut()
        .unwrap()
        .remove(contract::FAMILY[1]);
    assert!(projected_previous(&plan, &bad).is_err());
    let mut bad = prior.clone();
    bad[contract::FIELD][1]["token_sha256"] = json!("f".repeat(64));
    assert!(projected_previous(&plan, &bad).is_err());
}
#[test]
#[ignore = "Root readonly genuine2300 projection retains strict unrelated-role census equality"]
fn actual2300_composed_inherited_view_rejects_missing_or_extra_unrelated_roles() {
    let (prior, plan, task) = fixture();
    let expected = projected_previous(&plan, &prior).unwrap();
    let mut comparison: BTreeMap<String, Value> =
        serde_json::from_value(expected["unit_census"].clone()).unwrap();
    for (name, row) in
        serde_json::from_value::<BTreeMap<String, Value>>(task["native"].clone()).unwrap()
    {
        assert!(comparison.insert(name, row).is_none());
    }
    let route = route(&prior, &plan, &task);
    let accepted = route.inherited_native(&comparison).unwrap();
    let name = accepted.keys().next().unwrap().clone();
    let mut missing = comparison.clone();
    missing.remove(&name);
    assert!(route.inherited_native(&missing).is_err());
    let mut extra = comparison.clone();
    extra.insert(
        "foreign-unrelated.service".into(),
        json!({"Id":"foreign-unrelated.service"}),
    );
    assert!(route.inherited_native(&extra).is_err());
    let mut changed = comparison.clone();
    changed.get_mut(&name).unwrap()["unrelated_value_mutation"] = json!(true);
    assert_eq!(
        route.inherited_native(&changed).unwrap()[&name]["unrelated_value_mutation"],
        true
    );
    // This gate checks population only. Preserve changed values for the caller's
    // existing strict native comparison instead of normalizing them away.
}
