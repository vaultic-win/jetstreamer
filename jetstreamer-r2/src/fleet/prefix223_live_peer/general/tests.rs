//! Retained metadata only. Passing these tests never qualifies a live owner.
use super::*;

fn fixture(name: &str) -> Value {
    serde_json::from_str(match name {
        "fleet" => include_str!("fixtures/fleet237-projection.json"),
        "launch" => include_str!("fixtures/launch237.json"),
        "first" => include_str!("fixtures/first-fire237.json"),
        "plan" => include_str!("fixtures/plan237.json"),
        "guard" => include_str!("fixtures/guard237.json"),
        _ => unreachable!(),
    })
    .unwrap()
}

#[test]
fn actual_ordinary237_metadata_is_bound_without_becoming_a_private_diagnostic() {
    for (bytes, expected) in [
        (
            include_bytes!("fixtures/launch237.json").as_slice(),
            LAUNCH_SHA,
        ),
        (
            include_bytes!("fixtures/first-fire237.json").as_slice(),
            FIRST_SHA,
        ),
        (include_bytes!("fixtures/plan237.json").as_slice(), PLAN_SHA),
        (
            include_bytes!("fixtures/guard237.json").as_slice(),
            "e047f2198f88b46cb7c7f5b5d95160f310c11905bcc161f9bc1ca51b0e20955f",
        ),
    ] {
        assert_eq!(hex_lower(&Sha256::digest(bytes)), expected);
    }
    let f = fixture("fleet");
    shape(&f).unwrap();
    assert_eq!(
        names(&f).unwrap(),
        [UNIT.to_owned()].into_iter().collect::<BTreeSet<_>>()
    );
    assert!(f["active"][0].get("ordinary_replay_claim").is_none());
    validate_provenance(&fixture("launch"), &fixture("first"), &fixture("plan")).unwrap();
    assert_eq!(selector(UNIT), Some((GUARD, RECEIPTS)));
    assert_eq!(
        selector("horizon-qualify-237-general-target1-v1.service"),
        None
    );
    // Exercise the enclosing real roster, not only the new profile's selector.
    assert_eq!(
        super::super::roster(&f).unwrap(),
        [UNIT.to_owned()].into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn ordinary_controller_aliases_are_lossless_and_distinct_controllers_reject() {
    let f = fixture("fleet");
    let row = &f["active"][0];
    assert_eq!(
        singleton227_admission::active_owner(row).unwrap(),
        &row["producer"]
    );
    let mut changed = row.clone();
    changed["controller"]["MainPID"] = json!("2030543");
    assert!(singleton227_admission::active_owner(&changed).is_err());
    let mut private = row.clone();
    private["phase"] = json!("verification");
    assert!(singleton227_admission::active_owner(&private).is_err());
    let mut ambiguous = row.clone();
    ambiguous["unit"] = row["producer"].clone();
    assert!(singleton227_admission::active_owner(&ambiguous).is_err());
    let mut unknown = f;
    for key in ["producer", "controller"] {
        unknown["active"][0][key]["Id"] = json!("unmodeled-ordinary.service");
    }
    // Parsing a genuine alias never supplies a missing closed resource profile.
    assert!(singleton227_admission::active_owner(&unknown["active"][0]).is_ok());
    assert!(super::super::roster(&unknown).is_err());
}

#[test]
fn derived_arithmetic_view_preserves_raw_census_failed_history_and_unrelated_owners() {
    let mut f = fixture("fleet");
    f["failed_history"] = json!([{"epoch":223,"failed_original":"retained"}]);
    let auxiliary =
        json!({"epoch":235,"phase":"source-qa","producer":{"Id":"bounded-auxiliary.service"}});
    f["active"].as_array_mut().unwrap().push(auxiliary.clone());
    let saved = f.clone();
    let view = without(&f).unwrap();
    assert_eq!(f, saved);
    assert_eq!(view["active"], json!([auxiliary]));
    for key in ["unit_census", "epochs", "failed_history", "schema"] {
        assert_eq!(view[key], f[key]);
    }
    assert_eq!(GROWTH, 620_000_000_000);
    assert_eq!(FLOOR, 749_249_191_922);
}

#[test]
fn duplicates_replaced_invocations_wrong_phase_and_discarded_source_gates_reject() {
    let f = fixture("fleet");
    let row = &f["active"][0];
    let mut duplicate = f.clone();
    duplicate["active"]
        .as_array_mut()
        .unwrap()
        .push(row.clone());
    assert!(shape(&duplicate).is_err());
    for (path, value) in [
        ("/active/0/epoch", json!(238)),
        ("/active/0/phase", json!("verification")),
        ("/active/0/producer/InvocationID", json!("a".repeat(32))),
        ("/active/0/producer/NRestarts", json!("1")),
        ("/active/0/producer/MainPID", json!("1")),
        ("/active/0/producer/ActiveState", json!("inactive")),
        ("/epochs/0/gate_evidence", json!([])),
        ("/unit_census", json!({})),
    ] {
        let mut changed = f.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(shape(&changed).is_err(), "accepted changed {path}");
    }
    let mut private = f;
    private["active"][0]["ordinary_replay_claim"] = json!(false);
    assert!(shape(&private).is_err());
}

#[test]
fn actual_guard_plan_and_full_growth_floor_are_not_relaxed() {
    let (l, first, p) = (fixture("launch"), fixture("first"), fixture("plan"));
    for (path, value) in [
        ("/unit", json!("another.service")),
        ("/invocation_id", json!("a".repeat(32))),
        ("/worker_root", json!("/different-root")),
        ("/receipt_directory", json!("/different-receipts")),
        ("/maximum_root_physical_bytes", json!(GROWTH - 1)),
        ("/minimum_free_bytes", json!(FLOOR - 1)),
    ] {
        let mut changed = p.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            validate_provenance(&l, &first, &changed).is_err(),
            "accepted changed {path}"
        );
    }
    let mut changed = first;
    changed["guard"]["plan_sha256"] = json!("a".repeat(64));
    assert!(validate_provenance(&l, &changed, &p).is_err());
}

#[test]
fn genuine_guard_receipt_and_every_protective_obligation_remain_required() {
    let g = fixture("guard");
    let t = g["recorded_unix_seconds"].as_u64().unwrap();
    guard_shape(&g, t, t).unwrap();
    for (path, value) in [
        ("/plan_sha256", json!("a".repeat(64))),
        ("/guard_sha256", json!("a".repeat(64))),
        ("/producer/invocation_id", json!("a".repeat(32))),
        ("/producer/pid", json!(1)),
        ("/producer_stop_enabled", json!(false)),
        ("/maximum_root_physical_bytes", json!(GROWTH - 1)),
        ("/minimum_free_bytes", json!(FLOOR - 1)),
        ("/root_physical_observation/exceeds_budget", json!(true)),
        (
            "/root_physical_observation/conservative_physical_bytes",
            json!(GROWTH + 1),
        ),
        ("/workers", json!([])),
        ("/workers", json!([[1, 1], [2, 1]])),
        ("/trip_reason", json!("disk-floor")),
        ("/worker_observation_error", json!("unavailable")),
        ("/target_handoff", json!({})),
        ("/r2_mutations", json!(true)),
    ] {
        let mut changed = g.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            guard_shape(&changed, t, t).is_err(),
            "accepted changed {path}"
        );
    }
    assert!(guard_shape(&g, t + 1, t + 1).is_err());
    assert!(guard_shape(&g, t, t - 1).is_err());
    assert!(guard_shape(&g, t, t + 1801).is_err());
}

#[test]
fn full_future_memory_and_independent_guard_cap_are_additive() {
    for page in [4096, 65536] {
        let (cap, high) = (MEMORY / page * page, HIGH / page * page);
        assert_eq!(
            memory_growth(cap, high, high, 0, GUARD_MEMORY, page).unwrap(),
            cap - high + GUARD_MEMORY
        );
        assert_eq!(
            memory_growth(cap, high, cap, 0, GUARD_MEMORY, page).unwrap(),
            GUARD_MEMORY
        );
        assert!(memory_growth(cap, high, high, 0, 0, page).is_err());
        assert!(memory_growth(cap - page, high, high, 0, GUARD_MEMORY, page).is_err());
        assert!(memory_growth(cap, high, cap + 1, 0, GUARD_MEMORY, page).is_err());
        assert!(memory_growth(cap, high, high, 1, GUARD_MEMORY, page).is_err());
    }
}

#[test]
fn saved_memory_receipts_cannot_drop_the_guard_or_change_the_original_owner() {
    let page = 4096;
    let (cap, high) = (MEMORY / page * page, HIGH / page * page);
    let row = json!({"unit":UNIT,"invocation_id":IID,"hard_memory_cap_bytes":cap,
        "kernel_memory_high_bytes":high,"current_cgroup_charge_bytes":high,"memory_swap_max_bytes":0,
        "guard_hard_memory_reserved_bytes":GUARD_MEMORY,"host_page_size_bytes":page,
        "remaining_hard_memory_growth_bytes":cap-high+GUARD_MEMORY});
    super::super::validate_saved_row(&row).unwrap();
    for (key, value) in [
        ("guard_hard_memory_reserved_bytes", json!(0)),
        ("remaining_hard_memory_growth_bytes", json!(cap - high)),
        ("memory_swap_max_bytes", json!(1)),
        ("invocation_id", json!("a".repeat(32))),
    ] {
        let mut changed = row.clone();
        changed[key] = value;
        assert!(
            super::super::validate_saved_row(&changed).is_err(),
            "accepted changed {key}"
        );
    }
}
