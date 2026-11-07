//! Read-only regression over the preserved failed profile2 actual source graph.
use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Deserialize)]
struct Fixture {
    graph_values: BTreeMap<String, Value>,
    cohort: Value,
    sources: BTreeMap<String, Value>,
    base_fleet: Value,
    entry_fleet: Value,
}
fn fixture() -> Fixture {
    let path = std::path::Path::new(file!())
        .parent()
        .unwrap()
        .join("fixtures/input137-actual-profile2-guard-rollover-regression.json");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", sha2::Sha256::digest(&bytes)),
        "40f12ac32bb2cff4e2b4b56274f8addd2a45e92feda80fab02115322ac696f1a"
    );
    serde_json::from_slice(&bytes).unwrap()
}
impl Fixture {
    fn projected(&self) -> Result<Value> {
        // Historical profile 2 stays immutable. This test-only view strips its
        // already-censused old input row without granting it a production route.
        let unit = self.graph_values["download_plan"]["unit"]
            .as_str()
            .context("historical unit")?;
        let mut projected = self.entry_fleet.clone();
        ensure!(
            projected["unit_census"]
                .as_object()
                .context("historical census")?
                .contains_key(unit),
            "historical input row absent"
        );
        projected["unit_census"]
            .as_object_mut()
            .unwrap()
            .remove(unit);
        projected["pipelines"]
            .as_array_mut()
            .context("historical pipelines")?
            .retain(|r| r["unit"]["Id"] != unit);
        projected["active"]
            .as_array_mut()
            .context("historical active")?
            .retain(|r| !(r["epoch"] == 137 && r["unit"]["Id"] == unit));
        projected
            .as_object_mut()
            .unwrap()
            .remove("input137_history");
        Ok(projected)
    }
    fn check(&self) -> Result<()> {
        let projected = self.projected()?;
        let null = Value::Null;
        let empty = BTreeMap::new();
        let evidence = Evidence {
            observer: &self.graph_values["observer"],
            fleet: &self.entry_fleet,
            fleet_plan: &self.graph_values["entry_plan"],
            prior_parent: &null,
            prior_completion: &null,
            prior_fleet_plan: &self.graph_values["base_plan"],
            transition: &null,
            prior_recovery: Some(&self.graph_values["base_frame"]),
            fleet_transition: None,
            capture_tool_sha: "",
            cohort183_transition: Some(&self.cohort),
            cohort183_sources: &self.sources,
            native154_transition: None,
            native154_sources: &empty,
        };
        // Exact immutable fixture bytes above bind the actual failed profile2
        // graph. Select the qualified historical producer context explicitly;
        // missing live /proc image is never interpreted as comparison success.
        let context=crate::terminal199_context::Retained::load(&crate::terminal199_context::Bound{
            path:original199_input_witness_consumer::CONTEXT_PATH.into(),
            sha256:original199_input_witness_consumer::CONTEXT_SHA.into(),
        })?;
        cached145_frame::input137_entry::existing_fleet_unchanged_retained(
            &evidence,
            &projected,
            &self.base_fleet,
            &context,
        )
    }
    fn guard_name(&self) -> String {
        self.entry_fleet["cached145_guard_census_rollover"]["proofs"][0]["unit"]
            .as_str()
            .unwrap()
            .into()
    }
    fn timer_name(&self) -> String {
        self.entry_fleet["cached145_guard_census_rollover"]["timer_proofs"][0]["unit"]
            .as_str()
            .unwrap()
            .into()
    }
}
#[test]
fn actual_failed_profile2_fleet_composes_both_completed_guard_families_without_mutating_raw() {
    let f = fixture();
    let before = serde_json::to_vec(&f.entry_fleet).unwrap();
    f.check().unwrap();
    assert_eq!(serde_json::to_vec(&f.entry_fleet).unwrap(), before);
    let projected = f.projected().unwrap();
    assert!(cached145_frame::existing_fleet_unchanged(&projected, &f.base_fleet).is_err());
}
#[test]
fn missing_raw_or_positive_credit_never_becomes_a_rollover_exception() {
    for case in 0..3 {
        let mut f = fixture();
        let proof = &mut f.entry_fleet["cached145_guard_census_rollover"];
        match case {
            0 => {
                proof["proofs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("after_raw_guard_sample_value");
            }
            1 => proof["resource_credit_bytes"] = json!(1),
            _ => {
                f.entry_fleet
                    .as_object_mut()
                    .unwrap()
                    .remove("cached145_guard_census_rollover");
            }
        }
        assert!(f.check().is_err(), "case {case}");
    }
}
#[test]
fn live_failed_queued_or_changed_guard_profile_is_rejected() {
    for (key, value) in [
        ("MainPID", "123"),
        ("Result", "exit-code"),
        ("Job", "123"),
        ("MemoryMax", "1073741824"),
    ] {
        let mut f = fixture();
        let name = f.guard_name();
        f.entry_fleet["cached145_guard_census_rollover"]["proofs"][0]["after_native"][key] =
            value.into();
        f.entry_fleet["unit_census"][&name][key] = value.into();
        assert!(f.check().is_err(), "{key}");
    }
}
#[test]
fn timer_identity_or_refire_configuration_is_not_projected() {
    for (key, value) in [
        ("InvocationID", "foreign"),
        (
            "TimersMonotonic",
            "{ OnActiveUSec=1s ; next_elapse=0 }\n{ OnUnitActiveUSec=31s ; next_elapse=1 }",
        ),
    ] {
        let mut f = fixture();
        let name = f.timer_name();
        f.entry_fleet["unit_census"][&name][key] = value.into();
        f.entry_fleet["cached145_guard_census_rollover"]["timer_proofs"][0]["after_native"][key] =
            value.into();
        assert!(f.check().is_err(), "{key}");
    }
}
#[test]
fn cached145_producer_or_capture_identity_cannot_borrow_guard_proof() {
    for case in 0..2 {
        let mut f = fixture();
        if case == 0 {
            let name = f.entry_fleet["cached145_guard_census_rollover"]["proofs"][0]["producer"]
                .as_str()
                .unwrap()
                .to_owned();
            f.entry_fleet["unit_census"][&name]["InvocationID"] = json!("foreign");
        } else {
            f.sources.get_mut("cached145.capture").unwrap()["owner"]["main_pid"] = json!(123);
        }
        assert!(f.check().is_err());
    }
}
#[test]
fn epoch199_owner_guard_command_or_timer_identity_cannot_be_changed() {
    for case in 0..4 {
        let mut f = fixture();
        match case {
            0 => {
                f.entry_fleet["unit_census"][ordinary199::PRODUCER]["InvocationID"] =
                    json!("foreign")
            }
            1 => f.entry_fleet["unit_census"][ordinary199::GUARD]["Job"] = json!("123"),
            2 => f.entry_fleet["epoch199_guard_census_before"]["ExecStart"] = json!("foreign"),
            _ => {
                f.entry_fleet["unit_census"][ordinary199::TIMER]["InvocationID"] = json!("foreign")
            }
        }
        assert!(f.check().is_err(), "case {case}");
    }
}
#[test]
fn unknown_fields_gate_changes_and_resource_promises_remain_strict() {
    for case in 0..3 {
        let mut f = fixture();
        f.check().unwrap();
        let original = f.entry_fleet.clone();
        match case {
            0 => f.entry_fleet["unknown_input_entry_exception"] = json!(true),
            1 => f.entry_fleet["epochs"][0]["state"] = json!("blocked-qualification"),
            _ => f.entry_fleet["epoch199_promises"]["physical_credit_bytes"] = json!(1),
        }
        assert_ne!(
            f.entry_fleet, original,
            "case {case} must change the fixture"
        );
        assert!(f.check().is_err(), "case {case}");
    }
}
