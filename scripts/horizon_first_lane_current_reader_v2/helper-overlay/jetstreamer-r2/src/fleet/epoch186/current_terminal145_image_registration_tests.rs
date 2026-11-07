//! Pin eligibility is separate from the complete production outer adapter.
use super::*;
fn selected() -> Value {
    serde_json::json!({"self_sha256":CURRENT_TERMINAL145_FRAME_CAPTURE_SHA.unwrap(),
        "epoch199_terminal_context":{"path":original199_input_witness_consumer::CONTEXT_PATH,
        "sha256":original199_input_witness_consumer::CONTEXT_SHA}})
}
#[test]
fn exact_new_image_can_route_selected_witness_without_changing_old_pin_scope() {
    let frame=selected();
    assert!(current_terminal145_capture_with_pin(&frame,CURRENT_TERMINAL145_FRAME_CAPTURE_SHA));
    assert!(typed_bridge_capture(&frame));
    assert!(qualified_retry0005_capture(&frame));
    assert!(qualified_cached145_capture(&frame));
    // The historical raw registry remains an independently supported selector.
    let mut original=frame.clone();original["epoch199_terminal_context"]=retained199_v2_selector();
    assert!(typed_bridge_capture(&original));
    assert!(!typed_bridge_capture_with_pin(&frame,CURRENT_TERMINAL145_FRAME_CAPTURE_SHA));
    original["self_sha256"]=serde_json::json!(LIVE145_CENSUS_FRAME_CAPTURE_SHA.unwrap());
    assert!(typed_bridge_capture(&original));
    original["epoch199_terminal_context"]=frame["epoch199_terminal_context"].clone();
    assert!(!typed_bridge_capture(&original));
}
#[test]
fn disabled_bad_image_foreign_context_and_recovery_selectors_cannot_register() {
    let frame=selected();
    assert!(!current_terminal145_capture_with_pin(&frame,None));
    assert!(!current_terminal145_capture_with_pin(&frame,Some("invalid")));
    for (key,value) in [("self_sha256",serde_json::json!("0".repeat(64))),
        ("epoch199_terminal_context",serde_json::json!({"foreign":true})),
        ("epoch199_http500_capture_registration",serde_json::json!({"foreign":true})),
        ("epoch199_http500_recovery_enrollment",serde_json::json!({"foreign":true}))] {
        let mut bad=frame.clone();bad[key]=value;
        assert!(!typed_bridge_capture(&bad),"{key}");
    }
    let mut bad=frame;bad["epoch199_terminal_context"]["sha256"]=serde_json::json!("0".repeat(64));
    assert!(!typed_bridge_capture(&bad));
}
#[test]
fn selected_image_and_context_without_full_sources_never_validate_outer_frame() {
    let empty=Value::Null;
    let sources=std::collections::BTreeMap::new();
    let evidence=contract::Evidence {observer:&empty,fleet:&empty,fleet_plan:&empty,
        prior_parent:&empty,prior_completion:&empty,prior_fleet_plan:&empty,transition:&empty,
        prior_recovery:None,fleet_transition:None,capture_tool_sha:CURRENT_TERMINAL145_FRAME_CAPTURE_SHA.unwrap(),
        native154_transition:None,cohort183_transition:None,cohort183_sources:&sources,native154_sources:&sources};
    assert!(typed_bridge_capture(&selected()));
    assert!(validate_typed_bridge_frame(&selected(),&evidence,&empty,0,&selected()["epoch199_terminal_context"]).is_err());
}
#[path = "current_terminal145_outer_adapter_tests.rs"]
mod complete_outer;
