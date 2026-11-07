//! Root-only regression over the preserved real successful2200 reader outputs.
//! No service, resource observation, current reader clock or admission is run.
use crate::{ContextInputs, fsutil as f, model::*, validate};
use serde_json::{Value, json};

const CAPTURE_SPEC: &str = "/usr/local/lib/jetstreamer/horizon-original199-parent-memory-capture2200-plan-20261107-v1/spec.json";
const CAPTURE_SPEC_SHA: &str = "8fe78abdf48a758b3a6a20ece011382d86816b9083f4e7d7464668ad685bb32d";
const READER: &str = "/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/d5362d2b7daa9af15414d808fc383d6631a4224f55c490c0203a80066c4285fd/proof.json";
const READER_SHA: &str = "218c7de8c153da927663427fadd0f644c31114f17f6cce3ce3dd8c059b34f38b";

fn row_index(raw: &Value) -> usize {
    let rows = raw["active_peer_allocations"].as_array().unwrap();
    let selected = rows.iter().enumerate().filter(|(_, row)| row["unit"] == PRODUCER)
        .map(|(index, _)| index).collect::<Vec<_>>();
    assert_eq!(selected.len(), 1);
    selected[0]
}

#[test]
#[ignore = "Root must bind preserved immutable2200 outputs and deny original199 DEPLOY/STATE reads"]
fn actual2200_witness_raw_rows_preserve_all_debt_and_reject_crossed_contexts() {
    let spec: CaptureSpec = serde_json::from_value(f::immutable(&Bound {
        path: CAPTURE_SPEC.into(), sha256: CAPTURE_SPEC_SHA.into(),
    }).unwrap()).unwrap();
    validate::policy(&spec.policy).unwrap();
    assert_eq!(spec.current_reader, Bound { path: READER.into(), sha256: READER_SHA.into() });
    let proof = f::immutable(&spec.current_reader).unwrap();
    let before = f::immutable(&f::bound(&proof["accounting_before"]).unwrap()).unwrap();
    let after = f::immutable(&f::bound(&proof["accounting"]).unwrap()).unwrap();
    let saved = serde_json::to_vec(&(&before, &after)).unwrap();
    let inputs = ContextInputs::for_current(&spec.policy, &spec.current).unwrap();
    assert!(inputs.retained.selected_inputs().is_some());
    let plan = f::json(&spec.current.fleet_plan).unwrap();
    assert_eq!(plan["epoch199_terminal_context"], json!(inputs.binding()));
    assert_ne!(json!(inputs.binding()), json!(spec.policy.terminal_context));
    crate::terminal(&spec.policy, &spec.current, &before, &after, &inputs).unwrap();

    for raw in [&before, &after] {
        // Reproduce the exact old failure without opening legacy runtime inputs.
        let legacy = validate::terminal_raw_row(raw).unwrap_err();
        assert!(format!("{legacy:#}").contains("raw193GiB/768GiB context"));
        validate::terminal_raw_row_for_context(raw, &inputs).unwrap();
        let index = row_index(raw);
        for context in [
            json!(spec.policy.terminal_context),
            Value::Null,
            json!({"path":"/another/context.json","sha256":inputs.binding().sha256}),
            json!({"path":inputs.binding().path,"sha256":"0".repeat(64)}),
        ] {
            let mut changed = raw.clone();
            changed["active_peer_allocations"][index]["terminal_context"] = context;
            assert!(validate::terminal_raw_row_for_context(&changed, &inputs).is_err());
        }
        for (key, value) in [
            ("memory_max_bytes", json!(RAW_MEMORY - 1)),
            ("parent_memory_bytes", json!(PARENT - 1)),
            ("controller_memory_bytes", json!(GIB / 2 - 1)),
            ("guard_memory_bytes", json!(GIB / 2 - 1)),
            ("data_reservation_bytes", json!(DATA - 1)),
            ("memory_credit_bytes", json!(1)),
            ("DATA_credit_bytes", json!(1)),
            ("credit_bytes", json!(1)),
            ("resource_release_qualified", json!(true)),
            ("ordinary_replay_claim", json!(true)),
            ("native_pool_suballocation", json!(true)),
            ("original_enrollment", json!({"path":"/foreign/enrollment.json","sha256":"a".repeat(64)})),
        ] {
            let mut changed = raw.clone();
            changed["active_peer_allocations"][index][key] = value;
            assert!(validate::terminal_raw_row_for_context(&changed, &inputs).is_err(), "{key}");
        }
        let mut duplicate = raw.clone();
        duplicate["active_peer_allocations"].as_array_mut().unwrap().push(raw["active_peer_allocations"][index].clone());
        assert!(validate::terminal_raw_row_for_context(&duplicate, &inputs).is_err());
        let mut reduced_data = raw.clone();
        for row in reduced_data["projected_obligations"].as_array_mut().unwrap() {
            if row["producer_invocation_id"] == PRODUCER_IID {
                row["outstanding_bytes"] = json!(DATA - 1);
            }
        }
        assert!(validate::terminal_raw_row_for_context(&reduced_data, &inputs).is_err());
        let mut double = raw.clone();
        double["current_owner_hard_limits"][PRODUCER] = json!(RAW_MEMORY);
        assert!(validate::terminal_raw_row_for_context(&double, &inputs).is_err());
    }
    // An unchanged genuine row cannot authorize a crossed request-plan binding.
    // Digest rejection happens before any retained context can be selected.
    let mut crossed = spec.current.clone();
    crossed.fleet_plan.sha256 = "0".repeat(64);
    assert!(ContextInputs::for_current(&spec.policy, &crossed).is_err());
    let mut crossed_top = after.clone();
    crossed_top["original199_terminal_context"] = json!(spec.policy.terminal_context);
    assert!(crate::terminal(&spec.policy, &spec.current, &before, &crossed_top, &inputs).is_err());
    assert_eq!(saved, serde_json::to_vec(&(&before, &after)).unwrap());
    crate::terminal(&spec.policy, &spec.current, &before, &after, &inputs).unwrap();
}
