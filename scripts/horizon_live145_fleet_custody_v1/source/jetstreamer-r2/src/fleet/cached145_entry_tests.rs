//! Route priority tests over complete authentic accepted0548 policy/native data.
//! Additions below are synthetic test values, never operational receipts.
use super::*;
fn fixture() -> Value {
    let v: Value =
        serde_json::from_slice(include_bytes!("cached145_entry_fixture0548.json")).unwrap();
    assert!(
        v["document_kind"]
            .as_str()
            .unwrap()
            .starts_with("TEST ONLY")
    );
    assert_eq!(
        v["fleet_bound"]["sha256"],
        "206866f5d23d239dcecb2c0b43c44f13bdb75c9fffd5331aceaaba938bb9ceb6"
    );
    v
}
fn prospective(f: &Value) -> Value {
    let mut p = f["plan"].clone();
    let unit = "horizon-qualify-145-cached-c7f55a7b7c7a5d22.service";
    p["previous_fleet"] = f["fleet_bound"].clone();
    p["output"] = json!("/test-only/prospective-cached145-entry.json");
    p["diagnostics"].as_array_mut().unwrap().push(json!({"epoch":145,"unit":unit,
        "invocation_id":"a".repeat(32),"scratch_path":"/home/sol/.jetstreamer-private/epoch145-cached-c7f55a7b7c7a5d22/work",
        "launch_receipt":{"path":"/var/lib/jetstreamer/epoch145-cached-c7f55a7b7c7a5d22/receipts/capture.json","sha256":"b".repeat(64)}}));
    p["tracked_units"]
        .as_array_mut()
        .unwrap()
        .extend(family(unit).unwrap().into_iter().map(Value::String));
    p["admission_transition_guard"] = json!({"path":"/test-only/actual-first-guard-not-yet-created.json","sha256":"c".repeat(64)});
    p
}
fn selected(f: &Value, p: &Value) -> bool {
    select(
        &f["fleet"],
        &f["plan"],
        &f["plan"],
        p,
        // The real call site gets sample from the independently bound observer.
        "2026-11-01T05:48:09Z",
    )
    .is_ok_and(|v| v.is_some())
}
#[test]
fn actual0548_synthetic_entry_selects_guard_route_before_inherited_metadata() {
    let f = fixture();
    let p = prospective(&f);
    assert!(!f["plan"]["metadata_event"].is_null());
    assert_eq!(p["metadata_event"], f["plan"]["metadata_event"]);
    let selection = select(
        &f["fleet"],
        &f["plan"],
        &f["plan"],
        &p,
        f["fleet"]["sampled_at_utc"].as_str().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(cached145::namespace(&selection.claim));
    assert_eq!(selection.family.len(), 4);
    assert_eq!(selection.claim.epoch, 145);
}
#[test]
fn actual0548_original_route_and_other_diagnostic_admissions_are_unchanged() {
    let f = fixture();
    assert!(!selected(&f, &f["plan"]));
    let mut p = prospective(&f);
    p["diagnostics"].as_array_mut().unwrap().last_mut().unwrap()["epoch"] = json!(146);
    assert!(!selected(&f, &p));
    let mut p = prospective(&f);
    p["admission_transition_guard"] = Value::Null;
    assert!(!selected(&f, &p));
}
#[test]
fn actual0548_entry_rejects_inherited_policy_gate_metadata_and_owner_mutations() {
    let f = fixture();
    for mode in 0..8 {
        let mut p = prospective(&f);
        match mode {
            0 => p["metadata_event"] = Value::Null,
            1 => p["gates"]["199"]["state"] = json!("live-replay"),
            2 => {
                p["pipeline_claims"].as_array_mut().unwrap().remove(0);
            }
            3 => {
                p["diagnostics"].as_array_mut().unwrap().remove(0);
            }
            4 => p["unexpected_policy_override"] = json!(true),
            5 => p["observer"]["sha256"] = json!("f".repeat(64)),
            6 => {
                p["diagnostics"].as_array_mut().unwrap().last_mut().unwrap()["invocation_id"] =
                    json!("foreign")
            }
            _ => {
                p["diagnostics"].as_array_mut().unwrap().last_mut().unwrap()["launch_receipt"]["path"] =
                    json!("/other/capture.json")
            }
        };
        assert!(!selected(&f, &p), "mode {mode}");
    }
}
#[test]
fn actual0548_entry_rejects_missing_duplicate_and_extra_native_roles_or_claims() {
    let f = fixture();
    for mode in 0..5 {
        let mut p = prospective(&f);
        match mode {
            0=>{p["tracked_units"].as_array_mut().unwrap().pop();},
            1=>{let last=p["tracked_units"].as_array().unwrap().last().unwrap().clone();p["tracked_units"].as_array_mut().unwrap().push(last);},
            2=>p["tracked_units"].as_array_mut().unwrap().push(json!("unrelated.service")),
            3=>{let c=p["diagnostics"].as_array().unwrap().last().unwrap().clone();p["diagnostics"].as_array_mut().unwrap().push(c);},
            _=>p["diagnostics"].as_array_mut().unwrap().push(json!({"epoch":146,"unit":"other.service","invocation_id":"d".repeat(32),"scratch_path":"/other","launch_receipt":{"path":"/other/capture.json","sha256":"e".repeat(64)}})),
        };
        assert!(!selected(&f, &p), "mode {mode}");
    }
}
#[test]
fn actual0548_entry_rejects_crossed_predecessor_sample_scope_or_prior_admission() {
    let f = fixture();
    let p = prospective(&f);
    for (k, v) in [
        ("sampled_at_utc", json!("2026-11-01T05:18:09Z")),
        ("first_epoch", json!(201)),
        (
            "admission_transition_guard",
            json!({"path":"/already-used","sha256":"e".repeat(64)}),
        ),
    ] {
        let mut bad = f.clone();
        bad["fleet"][k] = v;
        assert!(!selected(&bad, &p), "{k}");
    }
}

fn retained_fixture() -> (Value, Value, Value, Value) {
    let f = fixture();
    let entry = prospective(&f);
    let mut previous = f["fleet"].clone();
    previous["observer_receipt"] = entry["observer"]["path"].clone();
    previous["observer_sha256"] = entry["observer"]["sha256"].clone();
    previous["admission_transition_guard"] = entry["admission_transition_guard"].clone();
    for name in family("horizon-qualify-145-cached-c7f55a7b7c7a5d22.service").unwrap() {
        previous["unit_census"][&name] = json!({"Id":name});
    }
    let mut next = entry.clone();
    next["admission_transition_guard"] = Value::Null;
    next["observer"] =
        json!({"path":"/test-only/genuine-next-routine-sample.json","sha256":"d".repeat(64)});
    next["output"] = json!("/test-only/cached145-retained-next.json");
    next["previous_fleet"] =
        json!({"path":"/test-only/actual-entry-fleet.json","sha256":"e".repeat(64)});
    (f, entry, previous, next)
}
#[test]
fn actual0548_retained_route_accepts_direct_successor_and_keeps_original_metadata_policy() {
    let (f, entry, previous, next) = retained_fixture();
    let selected = select(&previous, &entry, &f["plan"], &next, "2026-11-01T06:18:09Z")
        .unwrap()
        .unwrap();
    assert_eq!(selected.mode, Mode::Retained);
    assert_eq!(next["metadata_event"], f["plan"]["metadata_event"]);
    assert_eq!(next["gates"], f["plan"]["gates"]);
}
#[test]
fn actual0548_retained_route_rejects_changed_capture_policy_guard_or_non_direct_clock() {
    let (f, entry, previous, next) = retained_fixture();
    for time in [
        "2026-11-01T05:48:09Z",
        "2026-11-01T06:18:08Z",
        "2026-11-01T06:48:09Z",
    ] {
        assert!(select(&previous, &entry, &f["plan"], &next, time).is_err());
    }
    for mode in 0..6 {
        let mut bad = next.clone();
        match mode {
            0 => {
                bad["diagnostics"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["invocation_id"] = json!("f".repeat(32))
            }
            1 => {
                bad["diagnostics"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["launch_receipt"]["sha256"] = json!("f".repeat(64))
            }
            2 => bad["admission_transition_guard"] = entry["admission_transition_guard"].clone(),
            3 => bad["metadata_event"] = Value::Null,
            4 => bad["gates"]["199"]["state"] = json!("live-replay"),
            _ => {
                bad["tracked_units"].as_array_mut().unwrap().pop();
            }
        }
        assert!(
            select(&previous, &entry, &f["plan"], &bad, "2026-11-01T06:18:09Z").is_err(),
            "mode {mode}"
        );
    }
}

#[test]
fn cached_entry_inherited_g7_campaign_preserves_all_other_native_owners() {
    let f = fixture();
    let previous = &f["fleet"];
    let inherited: BTreeMap<String, Value> = previous["unit_census"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let family = family("horizon-qualify-145-cached-c7f55a7b7c7a5d22.service").unwrap();
    let mut current = inherited.clone();
    for name in &family {
        current.insert(
            name.clone(),
            json!({"Id":name,"ActiveState":"active","SubState":"running"}),
        );
    }
    assert!(super::super::native154_event::campaign_owners(previous, &current, None).is_err());
    let projected = project_inherited_native(&current, previous, &family).unwrap();
    assert_eq!(projected, inherited);
    super::super::native154_event::campaign_owners(previous, &projected, None).unwrap();
    let mut unknown = current.clone();
    unknown.insert(
        "unaccounted.service".into(),
        json!({"Id":"unaccounted.service"}),
    );
    assert!(project_inherited_native(&unknown, previous, &family).is_err());
    let mut missing = current.clone();
    missing.remove(inherited.keys().next().unwrap());
    assert!(project_inherited_native(&missing, previous, &family).is_err());
    let protected = inherited
        .iter()
        .find(|(_, v)| {
            v["MainPID"].as_str().is_some_and(|p| p != "0")
                && v["ActiveState"] == "active"
                && v["SubState"] == "running"
        })
        .unwrap()
        .0;
    let mut changed = current;
    changed.get_mut(protected).unwrap()["InvocationID"] = json!("f".repeat(32));
    let projected = project_inherited_native(&changed, previous, &family).unwrap();
    assert!(super::super::native154_event::campaign_owners(previous, &projected, None).is_err());
}

#[test]
fn retained_gap_requires_complete_chain_and_does_not_relax_policy() {
    let (f, entry, previous, next) = retained_fixture();
    let gap = "2026-11-01T13:28:09Z";
    assert!(select_with_chain(&previous, &entry, &f["plan"], &next, gap, false).is_err());
    assert_eq!(
        select_with_chain(&previous, &entry, &f["plan"], &next, gap, true)
            .unwrap()
            .unwrap()
            .mode,
        Mode::Retained
    );
    let mut bad = next.clone();
    bad["gates"]["199"]["state"] = json!("live-replay");
    assert!(select_with_chain(&previous, &entry, &f["plan"], &bad, gap, true).is_err());
    let mut bad = next;
    bad["diagnostics"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["invocation_id"] = json!("f".repeat(32));
    assert!(select_with_chain(&previous, &entry, &f["plan"], &bad, gap, true).is_err());
}

#[test]
fn exact_live145_projection_restores_complete_cached_policy_and_preserves_other_rejections() {
 let f=fixture();let p=prospective(&f);let mut augmented=p.clone();
 augmented["tracked_units"].as_array_mut().unwrap().extend(horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::FAMILY.into_iter().map(|u|json!(u)));
 assert!(!selected(&f,&augmented));
 let projected=horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::project_plan(&augmented).unwrap();
 assert_eq!(projected,p);assert!(selected(&f,&projected));
 let mut crossed=augmented.clone();crossed["gates"]["199"]["state"]=json!("live-replay");
 assert!(!selected(&f,&horizon_recovered_resource_frame_typed_bridge_v1::live145_frame::project_plan(&crossed).unwrap()));
 assert_eq!(augmented["tracked_units"].as_array().unwrap().len(),p["tracked_units"].as_array().unwrap().len()+3);
}
