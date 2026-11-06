//! Bind the real protected-accounting v1 source table without inventing a top-level plan.
use crate::model::{Bound, Current};
use serde_json::{Value, json};
pub(super) fn matches(value: &Value, current: &Current) -> bool {
    if value["observer"] != json!(current.observer) || value["fleet"] != json!(current.fleet) {
        return false;
    }
    match value.get("schema") {
        Some(schema) if schema == "jetstreamer-current-protected-data-accounting-spec-v1" => {
            value["fleet_plan"] == json!(current.fleet_plan)
        }
        Some(schema) if schema == "jetstreamer-current-protected-data-accounting-v1" => {
            if value.get("fleet_plan").is_some() {
                return false;
            }
            let Ok(sources) =
                serde_json::from_value::<Vec<Bound>>(value["source_bindings"].clone())
            else {
                return false;
            };
            [&current.observer, &current.fleet, &current.fleet_plan]
                .into_iter()
                .all(|expected| {
                    sources
                        .iter()
                        .filter(|actual| actual.path == expected.path)
                        .count()
                        == 1
                        && sources.iter().filter(|actual| *actual == expected).count() == 1
                })
        }
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Current) {
        let v: Value = serde_json::from_str(include_str!(
            "../fixtures/actual-accounting-interface-0228.json"
        ))
        .unwrap();
        (
            v["raw_accounting_interface"].clone(),
            serde_json::from_value(v["current"].clone()).unwrap(),
        )
    }
    #[test]
    fn actual_v1_accounting_authenticates_the_plan_in_its_real_source_table() {
        let (v, c) = fixture();
        assert!(v.get("fleet_plan").is_none());
        assert!(matches(&v, &c));
        for expected in [&c.observer, &c.fleet, &c.fleet_plan] {
            assert_eq!(
                v["source_bindings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|x| x["path"] == json!(expected.path))
                    .count(),
                1
            );
        }
    }
    #[test]
    fn missing_duplicate_or_crossed_current_source_anchors_reject() {
        let (v, c) = fixture();
        for expected in [&c.observer, &c.fleet, &c.fleet_plan] {
            let mut missing = v.clone();
            missing["source_bindings"]
                .as_array_mut()
                .unwrap()
                .retain(|x| x["path"] != json!(expected.path));
            assert!(!matches(&missing, &c));
            let mut duplicate = v.clone();
            duplicate["source_bindings"]
                .as_array_mut()
                .unwrap()
                .push(json!(expected));
            assert!(!matches(&duplicate, &c));
            let mut crossed = v.clone();
            let row = crossed["source_bindings"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|x| x["path"] == json!(expected.path))
                .unwrap();
            row["sha256"] = json!("f".repeat(64));
            assert!(!matches(&crossed, &c));
        }
        for key in ["observer", "fleet"] {
            let mut bad = v.clone();
            bad[key]["sha256"] = json!("e".repeat(64));
            assert!(!matches(&bad, &c));
        }
    }
    #[test]
    fn malformed_source_bindings_unknown_schema_and_shadow_plan_reject() {
        let (v, c) = fixture();
        for bad in [
            Value::Null,
            json!("not a binding table"),
            json!([42]),
            json!([{"path":"x","sha256":5}]),
        ] {
            let mut x = v.clone();
            x["source_bindings"] = bad;
            assert!(!matches(&x, &c));
        }
        let mut x = v.clone();
        x["schema"] = json!("unknown-accounting-v2");
        assert!(!matches(&x, &c));
        let mut x = v.clone();
        x["fleet_plan"] = json!(c.fleet_plan);
        assert!(!matches(&x, &c));
        let mut x = v.clone();
        x["source_bindings"][0]["unexpected"] = json!(true);
        assert!(!matches(&x, &c));
    }
    #[test]
    fn direct_input_source_shape_keeps_its_existing_exact_plan_binding() {
        let (_, c) = fixture();
        let v = json!({"schema":"jetstreamer-current-protected-data-accounting-spec-v1","observer":c.observer,"fleet":c.fleet,"fleet_plan":c.fleet_plan});
        assert!(matches(&v, &c));
        let mut bad = v.clone();
        bad["fleet_plan"]["sha256"] = json!("a".repeat(64));
        assert!(!matches(&bad, &c));
        let mut bad = v.clone();
        bad["fleet_plan"] = Value::Null;
        assert!(!matches(&bad, &c));
        let mut bad = v.clone();
        bad["schema"] = Value::Null;
        assert!(!matches(&bad, &c));
    }
    #[test]
    fn actual_full_producer_input_spec_and_raw_accounting_share_the_same_tuple() {
        let (raw, current) = fixture();
        let spec: Value = serde_json::from_str(include_str!(
            "../fixtures/actual-complete-accounting-input-spec-0228.json"
        ))
        .unwrap();
        assert_eq!(
            spec["schema"],
            "jetstreamer-current-protected-data-accounting-spec-v1"
        );
        assert!(matches(&spec, &current));
        assert!(matches(&raw, &current));
        for key in ["observer", "fleet", "fleet_plan"] {
            let mut changed = spec.clone();
            changed[key]["sha256"] = json!("0".repeat(64));
            assert!(!matches(&changed, &current), "{key}");
        }
    }
}
