#![allow(dead_code)]
pub mod ordinary199;
pub mod terminal199_context;
#[cfg(test)]
mod installed_selected_core_control {
    use super::*;
    #[test]
    #[ignore = "explicit actual installed-context metadata-only control"]
    fn actual_selected_context_and_ordinary_proof_avoid_original_bodies() {
        let context = terminal199_context::Retained::load(&terminal199_context::Bound {
            path: original199_input_witness_consumer::CONTEXT_PATH.into(),
            sha256: original199_input_witness_consumer::CONTEXT_SHA.into(),
        }).unwrap();
        let binding = serde_json::to_value(context.original_enrollment()).unwrap();
        let proof = ordinary199::load_for_context(&binding, &context).unwrap().unwrap();
        proof.revalidate_inputs().unwrap();
        context.revalidate_inputs().unwrap();
        assert!(context.selected_inputs().is_some());
        let mut plan = serde_json::json!({
            "epoch199_enrollment": binding,
            "epoch199_terminal_context": {
                "path": original199_input_witness_consumer::CONTEXT_PATH,
                "sha256": original199_input_witness_consumer::CONTEXT_SHA
            },
            "tracked_units": []
        });
        let view = ordinary199::project_plan_for_context(&plan, &context).unwrap();
        assert!(view.get(ordinary199::FIELD).is_none());
        assert!(view.get(ordinary199::TERMINAL_FIELD).is_none());
        plan[ordinary199::TERMINAL_FIELD]["sha256"] = serde_json::json!("0".repeat(64));
        assert!(ordinary199::project_plan_for_context(&plan, &context).is_err());

        assert!(ordinary199::load_for_context(&serde_json::Value::Null, &context).is_err());
    }
}
