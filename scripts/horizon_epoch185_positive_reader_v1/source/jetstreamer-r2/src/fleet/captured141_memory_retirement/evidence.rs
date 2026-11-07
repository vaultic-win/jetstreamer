use crate::fleet::captured141_memory_retirement::{fsutil as f, historical as h, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;
pub fn fixed_terminal() -> Bound {
    Bound {
        path: TERMINAL.into(),
        sha256: TERMINAL_SHA.into(),
    }
}
pub fn fixed_proof() -> Bound {
    Bound {
        path: PROOF.into(),
        sha256: PROOF_SHA.into(),
    }
}
pub fn qualification(q: &Qualification) -> Result<()> {
    ensure!(
        q.program.path == Path::new(PROGRAM),
        "foreign retirement program"
    );
    f::bytes(&q.program, 128 << 20)?;
    let artifact = f::json(&q.artifact)?;
    ensure!(
        artifact["schema"] == "captured141-memory-retirement-qualified-artifact-v1"
            && artifact["program"] == json!(q.program)
            && artifact["prod_clippy_passed"] == true
            && artifact["test_clippy_passed"] == true
            && artifact["all_tests_passed_as_root"] == true
            && artifact["all_native_pids_drained"] == true
            && artifact["source_argv_compiler_dependencies_unchanged"] == true
            && artifact["features"] == json!([]),
        "unqualified retirement artifact"
    );
    let seal = f::json(&q.seal)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(Path::new(PROGRAM).parent().context("program parent")?)
            && seal["publication_authorized"] == false
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false
            && seal["r2_mutations"] == false,
        "normal Rust seal absent"
    );
    let members = seal["members"].as_array().context("sealed members")?;
    for (b, name) in [
        (&q.program, "jetstreamer-captured141-memory-retirement"),
        (&q.artifact, "artifact-proof.json"),
    ] {
        ensure!(
            members
                .iter()
                .filter(|v| v["name"] == name && v["sha256"] == b.sha256)
                .count()
                == 1,
            "qualified member not normally sealed"
        );
    }
    Ok(())
}
pub fn capability(b: &Bound, q: &Qualification) -> Result<()> {
    let v = f::json(b)?;
    ensure!(
        v["schema"] == "captured141-memory-retirement-static-capability-v1"
            && v["qualification"] == json!(q)
            && v["historical_inputs_validated"] == true
            && v["current_native_queries"] == 0
            && v["recording_performed"] == false
            && v["memory_credit_applied_bytes"] == 0,
        "crossed or unqualified capability"
    );
    Ok(())
}
pub fn existing_proof(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-terminal-legacy-current-memory-proof-v1"
            && v["diagnostic_only"] == true
            && v["live_budget_selection_changed"] == false
            && v["applied_budget_release_bytes"] == 0
            && v["DATA_credit_bytes"] == 0
            && v["all_DATA_promises_preserved"] == true,
        "old diagnostic proof gained authority"
    );
    let mut found = Vec::new();
    for end in ["before", "after"] {
        let rows = v[end]["active_peer_allocations"]
            .as_array()
            .context("full original proof peer census")?;
        let exact = rows
            .iter()
            .filter(|p| p["unit"] == h::UNIT && p["invocation_id"] == h::IID)
            .collect::<Vec<_>>();
        ensure!(
            exact.len() == 1,
            "exact captured epoch 141 absent or duplicated in full original proof"
        );
        let p = exact[0];
        ensure!(
            p["memory_max_bytes"] == h::MEMORY
                && p["data_reservation_bytes"] == h::DATA
                && p["memory_credit_bytes"] == 0
                && p["historical_debt"] == true
                && p["captured_but_unreleased"] == true
                && p["retained_terminal_DATA"] == true
                && p["qualified_early_terminal"] == json!(fixed_terminal()),
            "original 193 GiB/145 GiB promise differs"
        );
        found.push(p);
    }
    ensure!(
        found[0] == found[1],
        "historical proof captured epoch 141 changed"
    );
    Ok(())
}
pub struct Accepted {
    pub peer: Value,
    pub frame: Value,
    pub sampled: u64,
}
fn clock_contract(
    observer: &Value,
    fleet: &Value,
    frame: &Value,
    clock: Option<u64>,
) -> Result<u64> {
    let recorded = observer["recorded_at_utc"]
        .as_str()
        .context("observer v2 recorded clock missing or malformed")?;
    let sampled = fleet["sampled_at_utc"]
        .as_str()
        .context("fleet sampled clock missing or malformed")?;
    let framed = frame["sampled_at_utc"]
        .as_str()
        .context("Frame sampled clock missing or malformed")?;
    let at = f::utc(recorded)?;
    let sample = f::utc(sampled)?;
    let frame_at = f::utc(framed)?;
    ensure!(
        at == sample && frame_at == sample && recorded == sampled && framed == sampled,
        "observer recorded/fleet/Frame clocks conflict"
    );
    // The authentic observer v2 has no sampled alias. An added alias cannot override its required clock.
    if let Some(alias) = observer.get("sampled_at_utc") {
        let alias = alias.as_str().context("observer sampled alias malformed")?;
        ensure!(
            f::utc(alias)? == at && alias == recorded,
            "observer clock aliases conflict"
        );
    }
    if let Some(now) = clock {
        f::fresh(sample, now, 1800)?;
    }
    Ok(sample)
}
pub fn accepted(t: &Tuple, terminal: &Value, clock: Option<u64>) -> Result<Accepted> {
    fn input(b: &Bound) -> Result<Vec<u8>> {
        ensure!(
            b.path.extension().is_some_and(|e| e == "json"),
            "accepted metadata JSON required before opening"
        );
        f::bytes(b, 8 << 20)
    }
    accepted_bytes(
        t,
        terminal,
        clock,
        &input(&t.observer)?,
        &input(&t.fleet)?,
        &input(&t.fleet_plan)?,
        &input(&t.frame)?,
    )
}
pub(crate) fn accepted_bytes(
    t: &Tuple,
    terminal: &Value,
    clock: Option<u64>,
    observer_raw: &[u8],
    fleet_raw: &[u8],
    plan_raw: &[u8],
    frame_raw: &[u8],
) -> Result<Accepted> {
    for (b, raw) in [
        (&t.observer, observer_raw),
        (&t.fleet, fleet_raw),
        (&t.fleet_plan, plan_raw),
        (&t.frame, frame_raw),
    ] {
        ensure!(
            b.path.extension().is_some_and(|v| v == "json")
                && !raw.is_empty()
                && raw.len() <= 8 << 20
                && f::sha(raw) == b.sha256,
            "accepted fixture/input hash or metadata class differs"
        );
    }
    let observer: Value = serde_json::from_slice(observer_raw)?;
    let fleet: Value = serde_json::from_slice(fleet_raw)?;
    let plan: Value = serde_json::from_slice(plan_raw)?;
    let frame: Value = serde_json::from_slice(frame_raw)?;
    accepted_values(t, terminal, clock, &observer, &fleet, &plan, &frame)
}
// Initial epoch 185 enrollment preserves the genuine prelaunch Frame. Retained
// running/terminal states require the real current Frame. Typed lifecycle proof
// preserves original launch custody; actual current clocks and bindings stay raw.
fn accepted_frame_parent(
    t: &Tuple,
    plan: &Value,
    fleet: &Value,
    frame: &Value,
    clock: Option<u64>,
) -> Result<()> {
    let (expected_fleet, expected_plan) = if plan["epoch185_cold_startpre_registration"].is_null() {
        (json!(t.fleet), json!(t.fleet_plan))
    } else {
        let clock = clock.context("cold185 captured141 bridge requires genuine current clock")?;
        let actual = crate::fleet::cold185::enrollment::current_allocation(plan, clock)?
            .context("cold185 captured141 bridge lacks exact current native task")?;
        crate::fleet::cold185::enrollment::validate_reader_bridge(plan, fleet, &actual, clock)?;
        match actual["stage"].as_str() {
            Some("start-pre") => {
                ensure!(
                    actual["guard_pending"] == true,
                    "cold185 setup Frame without pending native guard"
                );
                (
                    actual["prior_fleet"].clone(),
                    actual["prior_fleet_plan"].clone(),
                )
            }
            Some("running" | "terminal") => {
                ensure!(
                    actual["guard_pending"] == false,
                    "cold185 retained Frame claims new setup authority"
                );
                (json!(t.fleet), json!(t.fleet_plan))
            }
            _ => anyhow::bail!("cold185 captured141 unknown retained lifecycle"),
        }
    };
    exact_frame_parent(frame, &json!(t.observer), &expected_fleet, &expected_plan)
}
fn exact_frame_parent(frame: &Value, observer: &Value, fleet: &Value, plan: &Value) -> Result<()> {
    ensure!(
        frame["accepted_resource_lineage"] == true
            && frame["bindings"]["observer"] == *observer
            && frame["bindings"]["fleet"] == *fleet
            && frame["bindings"]["fleet_plan"] == *plan,
        "captured141 genuine Frame has crossed observer, fleet or plan"
    );
    Ok(())
}

fn accepted_values(
    t: &Tuple,
    terminal: &Value,
    clock: Option<u64>,
    observer: &Value,
    fleet: &Value,
    plan: &Value,
    frame: &Value,
) -> Result<Accepted> {
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0
            && fleet["observer_receipt"] == json!(t.observer.path)
            && fleet["observer_sha256"] == t.observer.sha256
            && fleet["plan"] == json!(t.fleet_plan.path)
            && fleet["plan_sha256"] == t.fleet_plan.sha256
            && plan["observer"] == json!(t.observer),
        "crossed accepted tuple"
    );
    accepted_frame_parent(t, plan, fleet, frame, clock)?;
    let sampled = clock_contract(observer, fleet, frame, clock)?;
    crate::fleet::captured141_memory_retirement::native::historical_commands(
        &frame["early_terminal141_after"]["current_native"],
        terminal,
    )?;
    let raw_peer = &fleet["captured_unreleased141_debt"];
    crate::fleet::captured141_memory_retirement::proposal::dormant_proposal(
        terminal, raw_peer, frame,
    )?;
    // Mirror the existing qualified accounting annotation without changing the source fleet bytes.
    let mut peer = raw_peer.clone();
    peer["qualified_early_terminal"] = json!(fixed_terminal());
    crate::fleet::captured141_memory_retirement::proposal::dormant_proposal(
        terminal, &peer, frame,
    )?;
    Ok(Accepted {
        peer,
        frame: frame.clone(),
        sampled,
    })
}
pub fn spec(s: &Spec, clock: Option<u64>) -> Result<Accepted> {
    ensure!(
        s.schema == "captured141-memory-only-retirement-spec-v1"
            && s.terminal == fixed_terminal()
            && s.existing_proof == fixed_proof()
            && s.output_directory == Path::new(OUTPUT),
        "exact retirement spec differs"
    );
    qualification(&s.qualification)?;
    let t = f::json(&s.terminal)?;
    h::validate(&t)?;
    existing_proof(&f::json(&s.existing_proof)?)?;
    accepted(&s.accepted, &t, clock)
}
pub fn admission(b: &Bound, sb: &Bound, s: &Spec, clock: u64) -> Result<Bound> {
    ensure!(
        b.path.file_name().is_some_and(|v| v == "decision.json")
            && b.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer"))
            && b.path
                .parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("horizon-captured141-memory-retirement-admission-")),
        "admission namespace differs"
    );
    let v = f::json(b)?;
    ensure!(
        v["schema"] == "captured141-memory-only-retirement-admission-v1"
            && v["node"] == "node_02/dev-samjohnson"
            && v["spec"] == json!(sb)
            && v["accepted"] == json!(s.accepted)
            && v["qualification"] == json!(s.qualification)
            && v["recording_authorized"] == true
            && v["finalization_authorized"] == true
            && v["memory_max_bytes"] == 536870912u64
            && v["DATA_credit_bytes"] == 0
            && v["memory_budget_credit_applied_bytes"] == 0
            && v["healthy145_guards_preserved"] == true
            && v["all_other_promises_preserved"] == true,
        "recording not independently admitted"
    );
    f::fresh(
        v["recorded_unix_seconds"]
            .as_u64()
            .context("admission clock")?,
        clock,
        600,
    )?;
    let cb = f::bound_from(&v["static_capability"])?;
    capability(&cb, &s.qualification)?;
    Ok(cb)
}

#[cfg(test)]
mod accepted2018_tests {
    use super::*;
    const OBSERVER: &[u8] = include_bytes!("fixtures/accepted2018/observer.json");
    const FLEET: &[u8] = include_bytes!("fixtures/accepted2018/fleet.json");
    const PLAN: &[u8] = include_bytes!("fixtures/accepted2018/fleet_plan.json");
    const FRAME: &[u8] = include_bytes!("fixtures/accepted2018/frame.json");
    fn tuple() -> Tuple {
        serde_json::from_slice(include_bytes!("fixtures/accepted2018/bindings.json")).unwrap()
    }
    fn terminal() -> Value {
        serde_json::from_slice(include_bytes!("fixtures/terminal.json")).unwrap()
    }
    fn values() -> (Value, Value, Value, Value) {
        (
            serde_json::from_slice(OBSERVER).unwrap(),
            serde_json::from_slice(FLEET).unwrap(),
            serde_json::from_slice(PLAN).unwrap(),
            serde_json::from_slice(FRAME).unwrap(),
        )
    }
    #[test]
    fn complete_authentic_hash_bound_2018_tuple_accepts_recorded_observer_clock() {
        let (observer, fleet, _, frame) = values();
        assert!(observer.get("sampled_at_utc").is_none());
        let at = f::utc("2026-11-01T20:18:09Z").unwrap();
        let accepted = accepted_bytes(
            &tuple(),
            &terminal(),
            Some(at + 1),
            OBSERVER,
            FLEET,
            PLAN,
            FRAME,
        )
        .unwrap();
        assert_eq!(accepted.sampled, at);
        let mut expected_peer = fleet["captured_unreleased141_debt"].clone();
        assert!(expected_peer.get("qualified_early_terminal").is_none());
        expected_peer["qualified_early_terminal"] = json!(fixed_terminal());
        assert_eq!(accepted.peer, expected_peer);
        assert_eq!(accepted.frame, frame);
        assert_eq!(accepted.peer["memory_max_bytes"], h::MEMORY);
        assert_eq!(accepted.peer["data_reservation_bytes"], h::DATA);
    }
    #[test]
    fn missing_malformed_or_conflicting_recorded_clock_cannot_use_an_alias() {
        let (observer, fleet, _, frame) = values();
        for bad in [
            Value::Null,
            json!(1),
            json!("2026-02-30T20:18:09Z"),
            json!("2026-11-01T20:18:09+00:00"),
            json!("2026-11-01T20:18:10Z"),
        ] {
            let mut changed = observer.clone();
            changed["recorded_at_utc"] = bad;
            assert!(clock_contract(&changed, &fleet, &frame, None).is_err());
        }
        let mut missing = observer.clone();
        missing.as_object_mut().unwrap().remove("recorded_at_utc");
        missing["sampled_at_utc"] = fleet["sampled_at_utc"].clone();
        assert!(clock_contract(&missing, &fleet, &frame, None).is_err());
        for alias in [
            Value::Null,
            json!(1),
            json!("malformed"),
            json!("2026-11-01T20:18:10Z"),
        ] {
            let mut changed = observer.clone();
            changed["sampled_at_utc"] = alias;
            assert!(clock_contract(&changed, &fleet, &frame, None).is_err());
        }
    }
    #[test]
    fn fleet_frame_clock_conflict_future_and_stale_tuple_still_reject() {
        let (observer, fleet, _, frame) = values();
        let at = f::utc("2026-11-01T20:18:09Z").unwrap();
        for bad in [Value::Null, json!(1), json!("2026-11-01T20:18:10Z")] {
            let mut changed = frame.clone();
            changed["sampled_at_utc"] = bad;
            assert!(clock_contract(&observer, &fleet, &changed, None).is_err());
        }
        assert!(clock_contract(&observer, &fleet, &frame, Some(at - 1)).is_err());
        assert!(clock_contract(&observer, &fleet, &frame, Some(at + 1801)).is_err());
    }
    #[test]
    fn complete_tuple_bytes_cannot_be_tampered_or_bound_to_another_plan() {
        let mut changed = OBSERVER.to_vec();
        changed.push(b' ');
        assert!(accepted_bytes(&tuple(), &terminal(), None, &changed, FLEET, PLAN, FRAME).is_err());
        let mut t = tuple();
        t.fleet_plan.sha256 = "f".repeat(64);
        assert!(accepted_bytes(&t, &terminal(), None, OBSERVER, FLEET, PLAN, FRAME).is_err());
    }
    #[test]
    fn authentic_adapter_keeps_every_original_cross_binding_and_lineage_gate() {
        let (observer, fleet, plan, frame) = values();
        let t = tuple();
        let terminal = terminal();
        for pointer in ["/inventory/anomalies", "/observer_sha256", "/plan_sha256"] {
            let mut changed = fleet.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                accepted_values(&t, &terminal, None, &observer, &changed, &plan, &frame).is_err()
            );
        }
        let mut changed = plan.clone();
        changed["observer"] = Value::Null;
        assert!(accepted_values(&t, &terminal, None, &observer, &fleet, &changed, &frame).is_err());
        for pointer in [
            "/accepted_resource_lineage",
            "/bindings/observer",
            "/bindings/fleet",
            "/bindings/fleet_plan",
        ] {
            let mut changed = frame.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                accepted_values(&t, &terminal, None, &observer, &fleet, &plan, &changed).is_err()
            );
        }
    }
    #[test]
    fn raw_fleet_debt_cannot_borrow_a_foreign_or_duplicate_terminal_annotation() {
        let (observer, fleet, plan, frame) = values();
        let t = tuple();
        let terminal = terminal();
        let mut bad = fleet.clone();
        bad["captured_unreleased141_debt"]["qualified_early_terminal"] =
            json!({"path":"/foreign.json","sha256":"f".repeat(64)});
        assert!(accepted_values(&t, &terminal, None, &observer, &bad, &plan, &frame).is_err());
        let mut bad = fleet.clone();
        bad["captured_unreleased141_debt"]["source_bindings"]
            .as_array_mut()
            .unwrap()
            .push(json!(fixed_terminal()));
        assert!(accepted_values(&t, &terminal, None, &observer, &bad, &plan, &frame).is_err());
        let mut bad = fleet;
        bad["captured_unreleased141_debt"]["data_reservation_bytes"] = json!(0);
        assert!(accepted_values(&t, &terminal, None, &observer, &bad, &plan, &frame).is_err());
    }
}

#[cfg(test)]
mod cold185_frame_parent_tests {
    use super::*;
    #[test]
    fn exact_inherited_frame_parent_keeps_original_raw_bindings() {
        let observer = json!({"path":"/original-observer.json","sha256":"a".repeat(64)});
        let fleet = json!({"path":"/original-fleet.json","sha256":"b".repeat(64)});
        let plan = json!({"path":"/original-plan.json","sha256":"c".repeat(64)});
        let frame = json!({"accepted_resource_lineage":true,
            "bindings":{"observer":observer,"fleet":fleet,"fleet_plan":plan}});
        let before = frame.clone();
        exact_frame_parent(&frame, &observer, &fleet, &plan).unwrap();
        assert_eq!(frame, before);
        assert!(
            exact_frame_parent(&frame, &observer, &json!({"path":"/new-fleet.json"}), &plan)
                .is_err()
        );
    }
    #[test]
    fn inherited_frame_view_rejects_each_crossed_binding_and_missing_lineage() {
        let observer = json!({"path":"/observer.json","sha256":"a".repeat(64)});
        let fleet = json!({"path":"/fleet.json","sha256":"b".repeat(64)});
        let plan = json!({"path":"/plan.json","sha256":"c".repeat(64)});
        let original = json!({"accepted_resource_lineage":true,
            "bindings":{"observer":observer,"fleet":fleet,"fleet_plan":plan}});
        for pointer in [
            "/accepted_resource_lineage",
            "/bindings/observer",
            "/bindings/fleet",
            "/bindings/fleet_plan",
        ] {
            let mut bad = original.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                exact_frame_parent(&bad, &observer, &fleet, &plan).is_err(),
                "{pointer}"
            );
        }
    }
}
